use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash as _, Hasher as _};

use k8s_openapi::{
    api::{
        batch::{self, v1::Job},
        core::{
            self as kcore,
            v1::{EmptyDirVolumeSource, EnvVar, KeyToPath, SecretVolumeSource, Volume},
        },
        networking::v1::{
            NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
            NetworkPolicySpec,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::{
    Api,
    api::{Patch, PatchParams},
    runtime::reflector::Lookup as _,
};

/// Name of the Job pod's main container — the one running `ansible-playbook`, and the one whose
/// `/dev/termination-log` carries the recap the reconciler reads back (see `advance_applying_run`).
pub const ANSIBLE_CONTAINER_NAME: &str = "ansible-playbook";

/// `ttlSecondsAfterFinished` for the ansible Job: the operator never deletes the Job or its pod
/// itself, it leaves cleanup to Kubernetes' TTL controller so finished runs stay around briefly for
/// inspection, then get reaped instead of accumulating forever.
///
/// Default `ttlSecondsAfterFinished` when a `PlaybookPlan` doesn't set `spec.ttlSecondsAfterFinished`.
///
/// Should comfortably exceed the time the operator needs to consume a finished Job's result — the
/// reconciler reads the run's outcome from the Job's own termination message, so a Job reaped
/// before that (e.g. across a long operator outage) loses its recap. That no longer wedges the run
/// — `advance_applying_run` treats a missing finished Job as `Unknown` and lets it retry — but it
/// costs an unnecessary retry, so keep this generous. One hour is well clear of the seconds-scale
/// consume latency.
const DEFAULT_JOB_TTL_SECONDS_AFTER_FINISHED: i32 = 3600;

/// Silent floor for a plan-supplied `spec.ttlSecondsAfterFinished`. Below this, the same
/// reaped-before-consumed risk above becomes likely rather than theoretical, so anything smaller is
/// quietly raised to it rather than rejected.
const MIN_JOB_TTL_SECONDS_AFTER_FINISHED: i32 = 60;

/// Ceiling for `spec.verbosity`. Ansible's practically useful maximum is `-vvvv` (connection +
/// plugin debugging); higher values add nothing, so anything larger is silently clamped rather than
/// rejected — the same forgiving style as `MIN_JOB_TTL_SECONDS_AFTER_FINISHED`.
const MAX_VERBOSITY: u8 = 4;

/// Resolves the effective Job TTL for a plan: its `spec.ttlSecondsAfterFinished` clamped up to
/// `MIN_JOB_TTL_SECONDS_AFTER_FINISHED`, or the default when unset.
fn effective_job_ttl(plan: &v1beta1::PlaybookPlan) -> i32 {
    match plan.spec.ttl_seconds_after_finished {
        Some(v) => v.max(MIN_JOB_TTL_SECONDS_AFTER_FINISHED),
        None => DEFAULT_JOB_TTL_SECONDS_AFTER_FINISHED,
    }
}

use crate::{
    utils,
    v1beta1::{
        self, FilesSource, PlaybookPlan, PlaybookVariableSource, ResolvedInventoryGroup, SshConfig,
        controllers::reconcile_error::ReconcileError,
        labels,
        playbookplancontroller::{execution_evaluator::ExecutionHash, managed_ssh, paths},
    },
};

/// Builds the run's Job exactly as it will be created, except for the correlation to its `Play` —
/// that UID does not exist yet when the attempt is first prepared, so [`correlate_job_to_play`]
/// stamps it on immediately before every `create`.
///
/// **Must stay a pure function of its arguments.** The `Play` stores no copy of the result: a
/// resumed attempt rebuilds it from the live plan and the groups it recorded, relying on the
/// attempt's `preparationFingerprint` to establish that those are still the inputs it was prepared
/// with. Anything time- or environment-dependent leaking in here would make a resumed run create a
/// Job that differs from the one it committed to.
///
/// **Ordering is load-bearing:** this function *replaces* `spec.template.metadata` wholesale (see
/// the pod-template labels below), so it must always run **before** `correlate_job_to_play`.
/// Reversing the two would silently drop the Play UID annotation from the pod template, and
/// `validate_selected_job` would then reject the run's own Job — stranding a healthy run as
/// `Blocked` while it holds its host Leases.
pub fn create_job_blueprint(
    hash: &ExecutionHash,
    retry_count: u32,
    target_groups: &[ResolvedInventoryGroup],
    object: &PlaybookPlan,
) -> Result<batch::v1::Job, ReconcileError> {
    let pb_name = object
        .metadata
        .name
        .as_ref()
        .expect(".metadata.name must be set here");

    let pb_namespace = object
        .metadata
        .namespace
        .as_ref()
        .expect(".metadata.namespace must be set here");

    let pb_uid = object
        .metadata
        .uid
        .as_deref()
        .ok_or(ReconcileError::PreconditionFailed("uid not set"))?;

    let mut job = create_job_skeleton(object, object.spec.template.requirements.is_some())?;

    if has_managed_ssh_group(target_groups) {
        let secret_name = managed_ssh::client_cert_secret_name(hash);
        configure_job_for_managed_ssh_client_cert(&mut job, &secret_name);
    }

    let ssh_configs = distinct_static_inventory_ssh_configs(target_groups);
    if !ssh_configs.is_empty() {
        configure_job_for_ssh(&mut job, &ssh_configs);
    }

    configure_job_for_callback_plugin(&mut job);
    configure_job_for_node_affinity(&mut job, &managed_ssh_node_names(target_groups));

    job.metadata.namespace = Some(pb_namespace.into());

    // retry_count must be in the name — the hash alone is unchanged between retries of an
    // identical spec, so without it a new run's Job name would collide with a completed prior
    // run's and get silently skipped by the idempotency check.
    job.metadata.name = Some(job_name(pb_name, pb_uid, hash, retry_count));

    let job_labels: BTreeMap<String, String> = BTreeMap::from([
        (labels::PLAYBOOKPLAN_NAME.into(), pb_name.to_string()),
        (labels::PLAYBOOKPLAN_HASH.into(), hash.to_string()),
        (labels::COMPONENT.into(), labels::PLAYBOOK_COMPONENT.into()),
    ]);
    job.metadata.labels = Some(job_labels.clone());

    // The NetworkPolicy scoping managed-ssh proxy-pod ingress selects on the execution-hash
    // label of the actual running Pod, not just the Job object — Jobs don't carry their own
    // labels down to their Pods unless the pod template's own metadata sets them explicitly.
    if let Some(spec) = job.spec.as_mut() {
        spec.template.metadata = Some(ObjectMeta {
            labels: Some(job_labels),
            ..Default::default()
        });
    }

    Ok(job)
}

/// Names an attempt's Job — and, identically, its `Play` record.
///
/// The plan name is truncated to fit [`utils::MAX_DNS_LABEL_LEN`]. That cap is the Job's, not the
/// `Play`'s: a Job name becomes the `job-name` label value on its pods, so the apiserver validates it
/// as a DNS *label* while a custom resource may use the far longer subdomain form. Since the write-
/// ahead protocol records the `Play` before creating the Job, an unbounded name would be accepted
/// for the record and then rejected for the Job — leaving the attempt stuck in `Launching`, retried
/// every tick, renewing host Leases that block every other plan targeting those hosts. The readable
/// half gets whatever the cap leaves after `apply-`, the ten-symbol short id and the attempt
/// number — 44 characters while the attempt is a single digit, one fewer for every further digit —
/// so a plan named 45 characters or more already reaches that. The bound therefore belongs here,
/// where the name is minted, rather than on the two objects that inherit it.
/// `the_plan_name_half_is_truncated_from_45_characters` pins those numbers to the arithmetic.
///
/// **The short id covers the plan's UID as well as the execution hash, and that is what makes the
/// name safe to truncate.** The readable half is lossy, so two plans in one namespace whose names
/// agree over the truncated prefix would otherwise be told apart only by a short id derived from
/// inputs they may legitimately share — an identical playbook and Secrets. Colliding there is not
/// merely untidy: the losing plan's `Play` can be pruned while its Job is still under TTL, leaving
/// the other plan free to record an attempt at that name and then meet the foreign Job under it.
/// Recovery refuses a Job that does not carry the attempt's identity
/// (`reconciler::resume_launching_run`), so the run is not finalized against a Job it never created —
/// but while the operator keeps reconciling it, it renews its host Leases until the foreign Job is
/// removed. A terminal foreign Job with a TTL may eventually be reaped automatically; otherwise an
/// administrator must resolve the collision. Keying on the UID makes cross-plan collisions much less
/// likely, while the identity check bounds what one still costs at every path that could meet one.
///
/// Two *revisions of one plan* can still collide here — same UID, and the short id is ten symbols of
/// a 64-bit hash — which is exactly why attempt numbers are reserved plan-wide rather than per hash;
/// see `reconciler::select_job`.
pub(super) fn job_name(
    plan_name: &str,
    plan_uid: &str,
    hash: &ExecutionHash,
    retry_count: u32,
) -> String {
    let prefix = "apply-";
    let suffix = format!("-{}-{retry_count}", run_short_id(plan_uid, hash));
    let budget = utils::MAX_DNS_LABEL_LEN.saturating_sub(prefix.len() + suffix.len());
    format!("{prefix}{}{suffix}", plan_name_segment(plan_name, budget))
}

/// The readable, plan-naming half of a generated resource name: at most `budget` characters, and
/// safe to concatenate a `-`-prefixed suffix onto.
///
/// A plan name is a DNS *subdomain*, so it may contain dots; the names built from it are read as
/// subdomains too, and a dot in them starts a new label. Truncating a dotted name can therefore land
/// exactly on a dot and leave the suffix opening a label with a hyphen — `apply-my.-abcdefghij-1`,
/// which the apiserver rejects even though the plan's own name was perfectly valid. Dots are folded to
/// hyphens *before* truncating so the segment is a single label whatever the cut removes, and any
/// trailing hyphen is then trimmed so the suffix cannot produce a doubled separator at the join.
fn plan_name_segment(plan_name: &str, budget: usize) -> String {
    plan_name
        .chars()
        .map(|character| if character == '.' { '-' } else { character })
        .take(budget)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string()
}

/// How many symbols [`run_short_id`] mints. Ten, matching `reconciler::RUN_ID_LENGTH`, rather than
/// the five a cosmetic name suffix uses: the alphabet has 27 symbols, so five would leave only ~14
/// million values for a discriminator that two similarly-named plans depend on, against ~2e14 at ten.
/// It is *not* what makes adoption safe — that is the identity check in
/// `reconciler::job_at_recorded_name` — but a collision still costs a stalled run, so the extra five
/// characters are cheaper than the stall.
const RUN_SHORT_ID_LENGTH: usize = 10;

/// The `{shortid}` segment of a run name: the plan's identity folded together with the revision the
/// run applies. Deterministic, because a resumed attempt has to rebuild the exact name it committed
/// to — and both inputs are fixed for the life of an attempt.
fn run_short_id(plan_uid: &str, hash: &ExecutionHash) -> String {
    let mut hasher = twox_hash::XxHash3_64::new();
    plan_uid.hash(&mut hasher);
    (**hash).hash(&mut hasher);
    utils::generate_id_with_length(hasher.finish(), RUN_SHORT_ID_LENGTH)
}

pub async fn ensure_job_network_policy(
    client: kube::Client,
    operator_namespace: &str,
    hash: &ExecutionHash,
    target_groups: &[ResolvedInventoryGroup],
    plan: &PlaybookPlan,
    mut egress: Vec<NetworkPolicyEgressRule>,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::PreconditionFailed(
        "expected .metadata.namespace in PlaybookPlan",
    ))?;
    let name = plan.name().ok_or(ReconcileError::PreconditionFailed(
        "expected .metadata.name in PlaybookPlan",
    ))?;
    let uid = plan.uid().ok_or(ReconcileError::PreconditionFailed(
        "expected .metadata.uid in PlaybookPlan",
    ))?;

    if has_managed_ssh_group(target_groups) {
        egress.push(NetworkPolicyEgressRule {
            to: Some(vec![NetworkPolicyPeer {
                namespace_selector: Some(LabelSelector {
                    match_labels: Some(BTreeMap::from([(
                        "kubernetes.io/metadata.name".into(),
                        operator_namespace.into(),
                    )])),
                    ..Default::default()
                }),
                pod_selector: Some(LabelSelector {
                    match_labels: Some(BTreeMap::from([
                        (labels::PLAYBOOKPLAN_HASH.into(), hash.to_string()),
                        (
                            labels::COMPONENT.into(),
                            labels::MANAGED_SSH_PROXY_COMPONENT.into(),
                        ),
                    ])),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ports: Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::Int(managed_ssh::PROXY_SSH_PORT)),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
        });
    }

    let np_name = job_network_policy_name(&name, hash);
    let policy = NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(np_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![OwnerReference {
                api_version: PlaybookPlan::api_version(&()).into(),
                kind: PlaybookPlan::kind(&()).into(),
                name: name.to_string(),
                uid: uid.to_string(),
                controller: Some(true),
                block_owner_deletion: None,
            }]),
            labels: Some(BTreeMap::from([
                (labels::PLAYBOOKPLAN_NAME.into(), name.to_string()),
                (labels::PLAYBOOKPLAN_HASH.into(), hash.to_string()),
                (labels::COMPONENT.into(), labels::PLAYBOOK_COMPONENT.into()),
            ])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([
                    (labels::PLAYBOOKPLAN_NAME.into(), name.to_string()),
                    (labels::PLAYBOOKPLAN_HASH.into(), hash.to_string()),
                    (labels::COMPONENT.into(), labels::PLAYBOOK_COMPONENT.into()),
                ])),
                ..Default::default()
            }),
            policy_types: Some(vec!["Egress".into()]),
            egress: Some(egress),
            ..Default::default()
        }),
    };

    Api::<NetworkPolicy>::namespaced(client, &namespace)
        .patch(
            &np_name,
            &PatchParams::apply("ansible-operator").force(),
            &Patch::Apply(&policy),
        )
        .await?;
    Ok(())
}

/// Name of a run's egress `NetworkPolicy` in the plan's namespace.
///
/// The plan name is both truncated (for readability) *and* hashed to reduce collision risk.
/// Truncation alone is not enough: object names are capped at 63 characters, so two plans in one
/// namespace sharing a long common prefix and the same execution hash — identical playbook and
/// Secrets, which is plausible for templated or copy-pasted plans — would collapse onto the same
/// policy name. The write is a forced server-side apply, so that collision would be silent and
/// destructive: the second plan takes over the `controller: true` owner reference, and the first
/// plan's cleanup (a delete by this same name) then removes the second plan's policy mid-run.
/// Including the full name in the hash substantially reduces collision risk from shared prefixes.
pub(super) fn job_network_policy_name(plan_name: &str, hash: &ExecutionHash) -> String {
    let mut hasher = twox_hash::XxHash3_64::new();
    plan_name.hash(&mut hasher);
    let suffix = format!(
        "-{}-{}-egress",
        utils::generate_id(hasher.finish()),
        utils::generate_id(**hash)
    );
    let prefix = "playbook-";
    let budget = utils::MAX_DNS_LABEL_LEN.saturating_sub(prefix.len() + suffix.len());
    format!("{prefix}{}{suffix}", plan_name_segment(plan_name, budget))
}

/// Creates a Kubernetes Job with everything needed for basic Ansible execution, without any
/// connection-specifics. Unlike the old chroot-based model, this Job pod needs no node-level
/// privilege at all — hostPID/hostIPC/hostNetwork/privileged/nodeSelector all now live on the
/// ephemeral managed-ssh proxy pods instead (see `managed_ssh.rs`).
fn create_job_skeleton(
    plan: &v1beta1::PlaybookPlan,
    with_requirements: bool,
) -> Result<batch::v1::Job, ReconcileError> {
    let pb_name = plan.name().ok_or(ReconcileError::PreconditionFailed(
        "expected .metadata.name in PlaybookPlan",
    ))?;

    let pb_uid = plan.uid().ok_or(ReconcileError::PreconditionFailed(
        "expected .metadata.uid in PlaybookPlan",
    ))?;

    let mut job = batch::v1::Job::default();

    job.metadata.owner_references = Some(vec![OwnerReference {
        api_version: v1beta1::PlaybookPlan::api_version(&()).into(),
        kind: v1beta1::PlaybookPlan::kind(&()).into(),
        name: pb_name.to_string(),
        uid: pb_uid.into(),
        ..Default::default()
    }]);

    let variable_secrets: Vec<&String> = extract_secret_names_for_variables(plan).collect();

    let mut volumes = vec![kcore::v1::Volume {
        name: "playbook".into(),
        secret: Some(kcore::v1::SecretVolumeSource {
            secret_name: Some(pb_name.into()),
            ..Default::default()
        }),
        ..Default::default()
    }];

    let mut volume_mounts = vec![kcore::v1::VolumeMount {
        name: "playbook".into(),
        mount_path: paths::WORKSPACE_MOUNT_PATH.into(),
        ..Default::default()
    }];

    for secret_name in &variable_secrets {
        volumes.push(kcore::v1::Volume {
            name: secret_name.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(secret_name.to_string()),
                default_mode: Some(0o0400),
                items: Some(vec![KeyToPath {
                    key: "variables.yaml".into(),
                    path: "variables.yaml".into(),
                    mode: None,
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });

        volume_mounts.push(kcore::v1::VolumeMount {
            name: secret_name.to_string(),
            mount_path: format!("{}/vars/{secret_name}", paths::WORKSPACE_MOUNT_PATH),
            ..Default::default()
        });
    }

    for files_volume in extract_file_volumes(plan) {
        volumes.push(files_volume?);
        let volume = volumes.last().unwrap();

        volume_mounts.push(kcore::v1::VolumeMount {
            name: volume.name.clone(),
            mount_path: format!(
                "{}/files/{}",
                paths::WORKSPACE_MOUNT_PATH,
                volume.name.clone()
            ),
            ..Default::default()
        });
    }

    let mut init_containers = Vec::new();

    // Add an initcontainer to install collections (workaround until we can use image volumes)
    if with_requirements {
        volumes.push(kcore::v1::Volume {
            name: "collections".into(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        });

        volume_mounts.push(kcore::v1::VolumeMount {
            name: "collections".into(),
            mount_path: "/etc/ansible/collections".into(),
            ..Default::default()
        });

        let collections_installer = kcore::v1::Container {
            name: "download-collections".into(),
            image: Some(plan.spec.image.clone()),
            working_dir: Some(paths::WORKSPACE_MOUNT_PATH.into()),
            volume_mounts: Some(volume_mounts.clone()),
            command: Some(vec![
                "ansible-galaxy".into(),
                "install".into(),
                "-r".into(),
                "requirements.yml".into(),
            ]),
            security_context: plan.spec.security_context.as_ref().map(Into::into),
            ..Default::default()
        };

        init_containers.push(collections_installer);
    }

    let main_container = kcore::v1::Container {
        name: ANSIBLE_CONTAINER_NAME.into(),
        image: Some(plan.spec.image.clone()),
        working_dir: Some(paths::WORKSPACE_MOUNT_PATH.into()),
        volume_mounts: Some(volume_mounts),
        command: Some(render_ansible_command(plan, variable_secrets)),
        // The recap callback writes to /dev/termination-log and the reconciler reads it back from
        // this container's state.terminated.message. These are the Kubernetes defaults, set
        // explicitly so the dependency is legible and can't be silently mutated away.
        termination_message_path: Some("/dev/termination-log".into()),
        termination_message_policy: Some("File".into()),
        security_context: plan.spec.security_context.as_ref().map(Into::into),
        ..Default::default()
    };

    let pod_template = kcore::v1::PodTemplateSpec {
        metadata: None,
        spec: Some(kcore::v1::PodSpec {
            restart_policy: Some("Never".into()), // todo: maybe configurable
            service_account_name: plan.spec.service_account_name.clone(),
            automount_service_account_token: Some(plan.spec.service_account_name.is_some()),
            volumes: Some(volumes),
            containers: vec![main_container],
            init_containers: Some(init_containers),
            ..Default::default()
        }),
    };

    let job_spec = batch::v1::JobSpec {
        backoff_limit: Some(0), // todo: maybe configurable
        // Cleanup is Kubernetes' job (the TTL controller), not the operator's — see `effective_job_ttl`.
        ttl_seconds_after_finished: Some(effective_job_ttl(plan)),
        template: pod_template,
        ..Default::default()
    };

    job.spec = Some(job_spec);

    Ok(job)
}

fn has_managed_ssh_group(groups: &[ResolvedInventoryGroup]) -> bool {
    groups
        .iter()
        .any(|g| matches!(g, ResolvedInventoryGroup::ManagedSsh { .. }))
}

/// The real cluster Node names this run targets over managed-ssh. Only `ManagedSsh` groups map to
/// actual nodes; `StaticInventory` hosts are arbitrary hostnames/IPs that don't constrain pod
/// scheduling, so they're excluded.
fn managed_ssh_node_names(groups: &[ResolvedInventoryGroup]) -> Vec<String> {
    groups
        .iter()
        .filter_map(|g| match g {
            ResolvedInventoryGroup::ManagedSsh { hosts, .. } => Some(hosts.hosts.iter().cloned()),
            ResolvedInventoryGroup::Ssh { .. } => None,
        })
        .flatten()
        .collect()
}

/// Softly prefers scheduling the ansible Job pod *off* the nodes this run targets, so a playbook
/// that disrupts a node (reboot/drain) is less likely to kill its own controller pod mid-run.
/// Uses `preferredDuringScheduling…` (never `required`): a run targeting every node still schedules
/// normally — the `NotIn` term then matches no node and the preference is simply a no-op. Skipped
/// entirely when the run targets no managed-ssh nodes (e.g. StaticInventory-only).
fn configure_job_for_node_affinity(job: &mut Job, avoid_nodes: &[String]) {
    if avoid_nodes.is_empty() {
        return;
    }

    let affinity = kcore::v1::Affinity {
        node_affinity: Some(kcore::v1::NodeAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![
                kcore::v1::PreferredSchedulingTerm {
                    weight: 100,
                    preference: kcore::v1::NodeSelectorTerm {
                        match_expressions: Some(vec![kcore::v1::NodeSelectorRequirement {
                            key: "kubernetes.io/hostname".into(),
                            operator: "NotIn".into(),
                            values: Some(avoid_nodes.to_vec()),
                        }]),
                        ..Default::default()
                    },
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    if let Some(pod_spec) = job.spec.as_mut().and_then(|s| s.template.spec.as_mut()) {
        pod_spec.affinity = Some(affinity);
    }
}

/// Distinct `(StaticInventory name, SshConfig)` pairs referenced by this run's groups, deduped
/// by resource name — a run's Job pod needs one mounted SSH secret per distinct StaticInventory
/// it targets, not one per host-group (multiple groups can come from the same resource).
fn distinct_static_inventory_ssh_configs(
    groups: &[ResolvedInventoryGroup],
) -> Vec<(String, SshConfig)> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();

    for group in groups {
        if let ResolvedInventoryGroup::Ssh {
            static_inventory_name,
            config,
            ..
        } = group
            && seen.insert(static_inventory_name.clone())
        {
            result.push((static_inventory_name.clone(), config.clone()));
        }
    }

    result
}

/// Mounts one SSH secret per distinct `StaticInventory` referenced this run, each at its own
/// resource-name-keyed path (`paths::static_inventory_ssh_dir`) so multiple StaticInventories
/// with different credentials can coexist in the same Job pod without colliding.
fn configure_job_for_ssh(job: &mut Job, ssh_configs: &[(String, SshConfig)]) {
    job.spec.as_mut().and_then(|spec| {
        spec.template.spec.as_mut().map(|pod_spec| {
            let main_container = pod_spec
                .containers
                .first_mut()
                .expect("job should have a container");

            for (static_inventory_name, config) in ssh_configs {
                let volume_name = format!("ssh-{static_inventory_name}");

                pod_spec.volumes.get_or_insert_default().push(Volume {
                    name: volume_name.clone(),
                    secret: Some(SecretVolumeSource {
                        secret_name: Some(config.secret_ref.name.clone()),
                        default_mode: Some(0o0400),
                        ..Default::default()
                    }),
                    ..Default::default()
                });

                main_container
                    .volume_mounts
                    .get_or_insert_default()
                    .push(kcore::v1::VolumeMount {
                        name: volume_name,
                        mount_path: paths::static_inventory_ssh_dir(static_inventory_name),
                        ..Default::default()
                    });
            }
        })
    });
}

/// Mounts this run's managed-ssh client identity. The Secret is expected to already exist by the
/// time the Job is created (`managed_ssh::ensure_proxy_infra`'s `ensure_client_cert` step).
fn configure_job_for_managed_ssh_client_cert(job: &mut Job, secret_name: &str) {
    job.spec.as_mut().and_then(|spec| {
        spec.template.spec.as_mut().map(|pod_spec| {
            let main_container = pod_spec
                .containers
                .first_mut()
                .expect("job should have a container");

            pod_spec.volumes.get_or_insert_default().push(Volume {
                name: "managed-ssh-client".into(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(secret_name.to_string()),
                    default_mode: Some(0o0400),
                    ..Default::default()
                }),
                ..Default::default()
            });

            main_container
                .volume_mounts
                .get_or_insert_default()
                .push(kcore::v1::VolumeMount {
                    name: "managed-ssh-client".into(),
                    mount_path: paths::MANAGED_SSH_CLIENT_DIR.into(),
                    ..Default::default()
                });
        })
    });
}

/// Sets the env vars that make Ansible load and use the operator's per-host-outcome recap
/// callback (rendered into the workspace secret alongside playbook.yml/inventory.yml — see
/// `workspace.rs`), without disabling the default human-readable stdout callback.
fn configure_job_for_callback_plugin(job: &mut Job) {
    job.spec.as_mut().and_then(|spec| {
        spec.template.spec.as_mut().map(|pod_spec| {
            let main_container = pod_spec
                .containers
                .first_mut()
                .expect("job should have a container");

            main_container.env.get_or_insert_default().extend([
                EnvVar {
                    name: "ANSIBLE_CALLBACKS_ENABLED".into(),
                    value: Some("ansible_operator_recap".into()),
                    ..Default::default()
                },
                EnvVar {
                    name: "ANSIBLE_CALLBACK_PLUGINS".into(),
                    value: Some(paths::WORKSPACE_MOUNT_PATH.into()),
                    ..Default::default()
                },
            ]);
        })
    });
}

pub fn extract_secret_names_for_variables(pp: &PlaybookPlan) -> impl Iterator<Item = &String> {
    pp.spec
        .template
        .variables
        .as_ref()
        .into_iter()
        .flat_map(|variables| {
            variables.iter().filter_map(|v| match v {
                PlaybookVariableSource::Inline { inline: _ } => None,
                PlaybookVariableSource::SecretRef { secret_ref } => Some(&secret_ref.name),
            })
        })
}

pub fn extract_secret_names_for_files(pp: &PlaybookPlan) -> impl Iterator<Item = &String> {
    pp.spec
        .template
        .files
        .as_ref()
        .into_iter()
        .flat_map(|files| {
            files.iter().filter_map(|v| match v {
                FilesSource::Other { .. } => None,
                FilesSource::Secret { secret_ref, .. } => Some(&secret_ref.name),
            })
        })
}

/// Takes the mostly schemarless volumes defined the PlaybookPlan and turns them into
/// proper Kubernetes Volumes that can be used in a PodSpec. This is necessary because
/// we don't want to handle every possible kind of volume in our code.
///
/// Instead we use serialiation magic to turn whatever the user gave us into whatever
/// the currently targeted Kubernetes version supports. This can fail if the user tries
/// to use a volume kind that does not exist, hence each item in the Iterator has its
/// own Result.
fn extract_file_volumes(
    pp: &PlaybookPlan,
) -> impl Iterator<Item = Result<Volume, serde_json::Error>> {
    let files = pp.spec.template.files.as_ref();

    files.into_iter().flatten().map(|source| {
        let value = match source {
            FilesSource::Secret { name, secret_ref } => serde_json::to_value(kcore::v1::Volume {
                name: name.to_owned(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(secret_ref.name.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            })?,
            FilesSource::Other { name, extra } => {
                let mut volume = serde_json::to_value(extra)?;
                volume
                    .as_object_mut()
                    .unwrap()
                    .entry("name")
                    .or_insert(serde_json::to_value(name)?);

                volume
            }
        };
        serde_json::from_value::<Volume>(value)
    })
}

/// Builds the `ansible-playbook` invocation. Connection details no longer appear here at all —
/// each host's connection mechanism is expressed as inventory vars in the rendered
/// `inventory.yml` instead, so there's no more per-strategy `-c`/`-l`/`--private-key` branching.
fn render_ansible_command(
    plan: &v1beta1::PlaybookPlan,
    extra_vars_filepaths: Vec<&String>,
) -> Vec<String> {
    let static_vars_filenames: Vec<String> = plan
        .spec
        .template
        .variables
        .as_ref()
        .map(|variables| {
            variables
                .iter()
                .filter_map(|source| match source {
                    PlaybookVariableSource::SecretRef { secret_ref: _ } => None,
                    PlaybookVariableSource::Inline { inline: _ } => Some(()),
                })
                .enumerate()
                .map(|(index, _)| format!("static-variables-{index}.yml"))
                .collect()
        })
        .unwrap_or_default();

    let mut ansible_command = vec!["ansible-playbook".into()];

    if let Some(level) = plan.spec.verbosity.filter(|v| *v > 0) {
        let level = level.min(MAX_VERBOSITY);
        ansible_command.push(format!("-{}", "v".repeat(level as usize)));
    }

    ansible_command.extend(
        static_vars_filenames
            .iter()
            .flat_map(|path| ["--extra-vars".into(), format!("@{path}")]),
    );

    ansible_command.extend(extra_vars_filepaths.iter().flat_map(|path| {
        [
            "--extra-vars".into(),
            format!(
                "@{}/vars/{path}/variables.yaml",
                paths::WORKSPACE_MOUNT_PATH
            ),
        ]
    }));

    ansible_command.extend(["-i".into(), "inventory.yml".into()]);
    ansible_command.push("playbook.yml".into());

    ansible_command
}

#[cfg(test)]
mod tests {
    use crate::v1beta1::{PlaybookPlan, labels};

    #[test]
    fn test_extract_file_volumes_generates_correct_volumes() {
        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: OneShot
  inventoryRefs:
    - name: something
      staticInventory: blubb
  template:
    variables:
      - inline:
          key: value
          nested:
            otherkey: othervalue
      - secretRef:
          name: secret-with-variables
    files:
      - name: some-configs
        secretRef:
          name: secret-with-config-files
      - name: binary-assets
        image:
          reference: my.registry.tld/the-image:v2
          pullPolicy: IfNotPresent
    playbook: |
      - hosts: all
        tasks:
          - name: Echo someting
            ansible.builtin.command:
              command: echo Hello
        "#;

        let pp = serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap();

        let results = super::extract_file_volumes(&pp);
        let (oks, errs): (Vec<_>, Vec<_>) = results.partition(Result::is_ok);

        assert!(errs.is_empty(), "Some results were Err: {errs:#?}");

        let volumes: Vec<_> = oks.into_iter().map(Result::unwrap).collect();
        let volume1 = volumes.first().unwrap();
        let volume2 = volumes.get(1).unwrap();

        assert_eq!("some-configs", volume1.name);
        assert!(volume1.secret.is_some());
        assert_eq!(
            volume1.secret.as_ref().unwrap().secret_name,
            Some("secret-with-config-files".into())
        );

        assert_eq!("binary-assets", volume2.name);
        assert!(volume2.image.is_some());
        assert_eq!(
            volume2.image.as_ref().unwrap().reference,
            Some("my.registry.tld/the-image:v2".into())
        );
        assert_eq!(
            volume2.image.as_ref().unwrap().pull_policy,
            Some("IfNotPresent".into())
        );
    }

    #[test]
    fn render_ansible_command_has_no_connection_flags_and_uses_full_inventory() {
        use crate::v1beta1::controllers::playbookplancontroller::job_builder::render_ansible_command;

        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: OneShot
  inventoryRefs: []
  template:
    playbook: |
      - hosts: all
        tasks: []
        "#;
        let pp = serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap();

        let command = render_ansible_command(&pp, Vec::new());

        assert!(!command.iter().any(|arg| arg == "-c"));
        assert!(!command.iter().any(|arg| arg == "-l"));
        assert!(!command.iter().any(|arg| arg == "--private-key"));
        assert!(command.iter().any(|arg| arg == "inventory.yml"));
        assert!(command.iter().any(|arg| arg == "playbook.yml"));
        // No verbosity requested -> no -v flag at all.
        assert!(!command.iter().any(|arg| arg.starts_with("-v")));
    }

    #[test]
    fn render_ansible_command_maps_verbosity_to_v_flags() {
        use crate::v1beta1::controllers::playbookplancontroller::job_builder::render_ansible_command;

        let v_flags = |plan: &PlaybookPlan| -> Vec<String> {
            render_ansible_command(plan, Vec::new())
                .into_iter()
                .filter(|arg| arg.starts_with("-v"))
                .collect()
        };

        // Explicit 0 is treated the same as unset: no flag.
        let mut zero = minimal_plan();
        zero.spec.verbosity = Some(0);
        assert!(v_flags(&zero).is_empty());

        // A level renders as a single combined flag.
        let mut two = minimal_plan();
        two.spec.verbosity = Some(2);
        assert_eq!(v_flags(&two), vec!["-vv".to_string()]);

        // Above the ceiling is clamped to -vvvv, not rejected.
        let mut huge = minimal_plan();
        huge.spec.verbosity = Some(9);
        assert_eq!(v_flags(&huge), vec!["-vvvv".to_string()]);
    }

    /// Where truncation actually begins. Pinned because the number is arithmetic on three separate
    /// constants and is quoted in `job_name`'s own doc comment and in the user guide, which had
    /// both drifted to "roughly fifty" — an estimate that let a plan named 45 to 50 characters look
    /// safe when its name was already being cut.
    #[test]
    fn the_plan_name_half_is_truncated_from_45_characters() {
        use crate::utils::MAX_DNS_LABEL_LEN;
        use crate::v1beta1::MAX_PLAN_NAME_LEN;
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let name_of = |length: usize, attempt: u32| {
            super::job_name(&"n".repeat(length), "uid", &hash, attempt)
        };

        assert!(
            name_of(44, 1).contains(&"n".repeat(44)),
            "44 characters is the longest plan name that survives whole"
        );
        assert!(
            !name_of(45, 1).contains(&"n".repeat(45)),
            "45 is the first length that loses a character"
        );
        // Both sit exactly on the cap: the readable half is what absorbs the difference.
        assert_eq!(name_of(44, 1).len(), MAX_DNS_LABEL_LEN);
        assert_eq!(name_of(45, 1).len(), MAX_DNS_LABEL_LEN);

        // Every further digit of the attempt number takes another character off that half.
        assert!(!name_of(44, 10).contains(&"n".repeat(44)));
        assert!(name_of(43, 10).contains(&"n".repeat(43)));

        // Whatever the plan name and attempt, the result stays inside the cap a Job is validated
        // against — which is the property the truncation exists for.
        for length in [1, 44, 45, MAX_PLAN_NAME_LEN] {
            assert!(name_of(length, u32::MAX).len() <= MAX_DNS_LABEL_LEN);
        }
    }

    #[test]
    fn job_blueprint_names_by_retry_count_not_a_time_nonce() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;
        use kube::runtime::reflector::Lookup as _;

        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
  namespace: default
  uid: 11111111-1111-1111-1111-111111111111
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: OneShot
  inventoryRefs: []
  template:
    playbook: |
      - hosts: all
        tasks: []
        "#;
        let pp = serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap();
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());

        let attempt_1 = super::create_job_blueprint(&hash, 1, &[], &pp).unwrap();
        let attempt_2 = super::create_job_blueprint(&hash, 2, &[], &pp).unwrap();
        let attempt_1_again = super::create_job_blueprint(&hash, 1, &[], &pp).unwrap();

        let name_1 = attempt_1.name().unwrap().to_string();
        let name_2 = attempt_2.name().unwrap().to_string();
        let name_1_again = attempt_1_again.name().unwrap().to_string();

        assert_eq!(
            name_1, name_1_again,
            "same hash + same retry_count must be deterministic"
        );
        assert_ne!(
            name_1, name_2,
            "different retry_count for the same spec must produce a different name"
        );
        assert!(name_1.ends_with("-1"));
        assert!(name_2.ends_with("-2"));

        // The shortid portion stays the same across retries — it's the spec-version identifier.
        let shortid_1 = name_1.rsplit_once('-').unwrap().0;
        let shortid_2 = name_2.rsplit_once('-').unwrap().0;
        assert_eq!(shortid_1, shortid_2);
    }

    fn minimal_plan() -> PlaybookPlan {
        let yaml = r#"
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: an-example
  namespace: default
  uid: 11111111-1111-1111-1111-111111111111
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: OneShot
  inventoryRefs: []
  template:
    playbook: |
      - hosts: all
        tasks: []
        "#;
        serde_yaml::from_str::<PlaybookPlan>(yaml).unwrap()
    }

    #[test]
    fn managed_ssh_run_softly_prefers_scheduling_off_targeted_nodes() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;
        use crate::v1beta1::{ResolvedHosts, ResolvedInventoryGroup};

        let pp = minimal_plan();
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());
        let groups = vec![ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "workers".into(),
                hosts: vec!["node-a".into(), "node-b".into()],
            },
            tolerations: None,
            variables: None,
        }];

        let job = super::create_job_blueprint(&hash, 1, &groups, &pp).unwrap();
        let node_affinity = job
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .affinity
            .expect("affinity should be set for a managed-ssh run")
            .node_affinity
            .unwrap();

        // Soft only — a run targeting every node must still schedule, so this is never `required`.
        assert!(
            node_affinity
                .required_during_scheduling_ignored_during_execution
                .is_none()
        );

        let term = &node_affinity
            .preferred_during_scheduling_ignored_during_execution
            .unwrap()[0];
        assert_eq!(term.weight, 100);

        let req = &term.preference.match_expressions.as_ref().unwrap()[0];
        assert_eq!(req.key, "kubernetes.io/hostname");
        assert_eq!(req.operator, "NotIn");
        assert_eq!(
            req.values.as_ref().unwrap(),
            &vec!["node-a".to_string(), "node-b".to_string()]
        );
    }

    #[test]
    fn job_ttl_defaults_and_clamps_to_a_silent_minimum() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());
        let ttl = |plan: &PlaybookPlan| {
            super::create_job_blueprint(&hash, 1, &[], plan)
                .unwrap()
                .spec
                .unwrap()
                .ttl_seconds_after_finished
                .unwrap()
        };

        // Unset -> the operator's default (cleanup is the TTL controller's job, never the operator's).
        assert_eq!(
            ttl(&minimal_plan()),
            super::DEFAULT_JOB_TTL_SECONDS_AFTER_FINISHED
        );

        // Below the floor -> silently raised to the minimum, not rejected.
        let mut too_small = minimal_plan();
        too_small.spec.ttl_seconds_after_finished = Some(10);
        assert_eq!(ttl(&too_small), super::MIN_JOB_TTL_SECONDS_AFTER_FINISHED);

        // At/above the floor -> passed through unchanged.
        let mut explicit = minimal_plan();
        explicit.spec.ttl_seconds_after_finished = Some(7200);
        assert_eq!(ttl(&explicit), 7200);
    }

    #[test]
    fn static_inventory_only_run_gets_no_node_affinity() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;
        use crate::v1beta1::{ResolvedHosts, ResolvedInventoryGroup, SecretRef, SshConfig};

        let pp = minimal_plan();
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());
        let groups = vec![ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: "external".into(),
                hosts: vec!["ccu.fritz.box".into()],
            },
            static_inventory_name: "ccu".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef {
                    name: "ssh-key".into(),
                },
            },
            variables: None,
        }];

        let job = super::create_job_blueprint(&hash, 1, &groups, &pp).unwrap();
        assert!(
            job.spec.unwrap().template.spec.unwrap().affinity.is_none(),
            "StaticInventory hosts aren't cluster nodes, so nothing constrains placement"
        );
    }

    #[test]
    fn no_service_account_means_no_token_is_mounted() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let pp = minimal_plan();
        assert!(pp.spec.service_account_name.is_none());
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());

        let pod_spec = super::create_job_blueprint(&hash, 1, &[], &pp)
            .unwrap()
            .spec
            .unwrap()
            .template
            .spec
            .unwrap();

        assert_eq!(pod_spec.service_account_name, None);
        // Fail-closed: without a ServiceAccount named, the pod carries no API token.
        assert_eq!(pod_spec.automount_service_account_token, Some(false));
    }

    #[test]
    fn service_account_is_set_and_its_token_is_mounted() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let mut pp = minimal_plan();
        pp.spec.service_account_name = Some("playbook-sa".into());
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());

        let pod_spec = super::create_job_blueprint(&hash, 1, &[], &pp)
            .unwrap()
            .spec
            .unwrap()
            .template
            .spec
            .unwrap();

        assert_eq!(pod_spec.service_account_name, Some("playbook-sa".into()));
        assert_eq!(pod_spec.automount_service_account_token, Some(true));
    }

    #[test]
    fn plan_security_context_is_applied_to_both_job_containers() {
        use crate::v1beta1::PlaybookSecurityContext;
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let mut pp = minimal_plan();
        pp.spec.template.requirements = Some("collections: []".into());
        pp.spec.security_context = Some(PlaybookSecurityContext {
            allow_privilege_escalation: Some(false),
            ..Default::default()
        });
        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());

        let pod_spec = super::create_job_blueprint(&hash, 1, &[], &pp)
            .unwrap()
            .spec
            .unwrap()
            .template
            .spec
            .unwrap();

        assert_eq!(
            pod_spec.containers[0]
                .security_context
                .as_ref()
                .unwrap()
                .allow_privilege_escalation,
            Some(false)
        );
        assert_eq!(
            pod_spec.init_containers.unwrap()[0]
                .security_context
                .as_ref()
                .unwrap()
                .allow_privilege_escalation,
            Some(false)
        );
    }

    /// The budget this name has to fit: any plan name at all, inside the label cap a NetworkPolicy
    /// name is held to.
    ///
    /// The second half pins the readable half of the name. Two names that truncate to the same
    /// text still read as each other in `kubectl get netpol`, which the plan-name hash is what
    /// prevents.
    #[test]
    fn job_network_policy_name_fits_its_budget_and_stays_distinguishable() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN};
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        // A plan name is an object name, so the worst case it has to survive is a full subdomain.
        let hash = calculate_execution_hash("playbook", std::iter::empty());
        assert!(
            super::job_network_policy_name(&"a".repeat(MAX_DNS_SUBDOMAIN_LEN), &hash).len()
                <= MAX_DNS_LABEL_LEN
        );

        let long_prefix = "a".repeat(60);
        let first = super::job_network_policy_name(&format!("{long_prefix}-one"), &hash);
        let second = super::job_network_policy_name(&format!("{long_prefix}-two"), &hash);

        assert_ne!(first, second);
        assert!(first.len() <= MAX_DNS_LABEL_LEN);
        assert!(second.len() <= MAX_DNS_LABEL_LEN);
    }

    /// A Job name becomes the `job-name` label value on its pods, so it is bounded by the DNS *label*
    /// cap however long the plan's own (subdomain-length) name is. It has to hold for a large attempt
    /// number too: the number is reserved plan-wide and never restarts at 1, so it grows with the
    /// plan's history and eats into the same budget.
    ///
    /// This is not cosmetic. The `Play` is recorded under this name before the Job is created, and a
    /// custom resource accepts the longer subdomain form — so a name that only the Job rejects would
    /// strand the attempt in `Launching`, holding its host Leases while it retried forever.
    #[test]
    fn job_name_fits_the_label_budget_a_job_is_actually_validated_against() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN};
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());
        for plan_name in ["web", &"a".repeat(MAX_DNS_SUBDOMAIN_LEN)] {
            for attempt in [1, u32::MAX] {
                let name = super::job_name(plan_name, "plan-uid", &hash, attempt);
                assert!(
                    name.len() <= MAX_DNS_LABEL_LEN,
                    "{name} ({} chars) exceeds the Job name cap",
                    name.len()
                );
                assert!(name.starts_with("apply-"));
                assert!(name.ends_with(&format!("-{attempt}")));
            }
        }

        // A name that already fits keeps the documented `apply-{plan}-{shortid}-{n}` shape, with the
        // plan's own name intact — truncation must not perturb the ordinary case.
        assert_eq!(
            super::job_name("web", "plan-uid", &hash, 2),
            format!("apply-web-{}-2", super::run_short_id("plan-uid", &hash))
        );
    }

    /// Truncation makes the readable half of the name lossy, so the short id is what has to keep two
    /// plans apart — including the case truncation creates: identical long names beyond the cut, and
    /// an identical playbook and Secrets, so the execution hash matches too. Without the plan's UID
    /// in the short id these would be the same Job and `Play` name, and one plan's attempt could be
    /// finalized against the other's Job.
    #[test]
    fn long_plan_names_sharing_a_truncated_prefix_still_name_distinct_runs() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN};
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());
        let shared_prefix = "a".repeat(MAX_DNS_SUBDOMAIN_LEN - 4);

        let first = super::job_name(&format!("{shared_prefix}-one"), "uid-one", &hash, 1);
        let second = super::job_name(&format!("{shared_prefix}-two"), "uid-two", &hash, 1);

        assert_ne!(
            first, second,
            "two plans truncated to the same text must not share a run name"
        );
        assert!(first.len() <= MAX_DNS_LABEL_LEN);
        assert!(second.len() <= MAX_DNS_LABEL_LEN);

        // The same plan, on the other hand, has to name the same run every time it is asked — a
        // resumed attempt rebuilds the name it already committed to.
        assert_eq!(
            first,
            super::job_name(&format!("{shared_prefix}-one"), "uid-one", &hash, 1)
        );
    }

    /// Whether a generated name is a valid RFC 1123 DNS label — what a Job name and its `job-name`
    /// label value are held to, and the stricter half of what a `Play` (a subdomain) allows.
    fn is_dns_label(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= crate::utils::MAX_DNS_LABEL_LEN
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    /// A plan name is a DNS *subdomain*, so it may contain dots and the generated names must survive
    /// them. The case that actually broke is truncation landing exactly on a dot: the `-` starting
    /// the suffix would then open a new DNS label, which the apiserver rejects — for a plan name that
    /// was itself perfectly valid. Length alone would not have caught it, so this asserts syntax.
    #[test]
    fn generated_names_stay_valid_dns_labels_for_dotted_plan_names() {
        use crate::utils::MAX_DNS_LABEL_LEN;
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("- hosts: all", std::iter::empty());

        // Sweep every truncation point across a dotted name, so whichever one lands on (or just
        // after) a dot is covered rather than guessed at.
        for length in 1..=MAX_DNS_LABEL_LEN + 8 {
            let plan_name: String = std::iter::successors(Some(0usize), |n| Some(n + 1))
                .map(|n| if n % 8 == 7 { '.' } else { 'a' })
                .take(length)
                .collect();
            let plan_name = plan_name.trim_end_matches('.');
            if plan_name.is_empty() {
                continue;
            }

            for attempt in [1, 42, u32::MAX] {
                let name = super::job_name(plan_name, "plan-uid", &hash, attempt);
                assert!(is_dns_label(&name), "job name {name:?} is not a DNS label");
            }
            let policy = super::job_network_policy_name(plan_name, &hash);
            assert!(
                is_dns_label(&policy),
                "policy name {policy:?} is not a DNS label"
            );
        }

        // A name ending in hyphens before truncation must not leave one at the join either.
        for plan_name in ["web--", "web.", "a.b.c", &format!("{}.x", "a".repeat(39))] {
            let name = super::job_name(plan_name, "plan-uid", &hash, u32::MAX);
            assert!(is_dns_label(&name), "job name {name:?} is not a DNS label");
        }
    }
}
