use std::{
    collections::BTreeMap,
    hash::{Hash as _, Hasher as _},
};

use k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::OwnerReference};
use kube::runtime::reflector::Lookup;

use crate::{
    utils,
    v1beta1::{
        PlaybookPlan, ResolvedInventoryGroup, ansible,
        controllers::reconcile_error::ReconcileError, playbookplancontroller::paths,
    },
};

/// How many symbols the workspace name's short id carries. Ten, matching `job_builder`'s run short
/// id: the readable half is lossy, so the id is the only thing keeping two similarly-named plans
/// in one namespace apart, and it is also what a user would have to reproduce to name a Secret onto
/// this one.
const WORKSPACE_ID_LENGTH: usize = 10;

/// The name of the Secret [`render_secret`] renders a plan's workspace into.
///
/// **Deliberately not the plan's own name.** The workspace is written on every reconcile of a
/// running plan, with an ownerReference to the plan, through a server-side apply that claims
/// `playbook.yml`, `inventory.yml` and friends. Named after the plan, it lands on any Secret a user
/// happened to give the plan's name: their keys are overwritten, their object is adopted (so it is
/// garbage-collected when the plan goes), and if the plan also references it — the natural case,
/// one Secret named after the plan it feeds — every workspace write moves `execution_hash`
/// mid-run, and the plan replaces its own successful run forever.
///
/// The short id folds the plan's **UID**, not its inputs: the name has to be stable for the whole
/// life of a plan, including across revisions and resumed runs that rebuild the Job blueprint, and
/// two plans that share a truncated readable half must still get different names. A user can of
/// course still type this name; `reconciler::upsert_workspace_secret` refuses to write a Secret the
/// plan does not own, so that case is a clean, permanent failure rather than a silent one.
pub(super) fn workspace_secret_name(plan_name: &str, plan_uid: &str) -> String {
    let mut hasher = twox_hash::XxHash3_64::new();
    plan_uid.hash(&mut hasher);
    let suffix = format!(
        "-{}",
        utils::generate_id_with_length(hasher.finish(), WORKSPACE_ID_LENGTH)
    );
    let prefix = "workspace-";
    let budget = utils::MAX_DNS_LABEL_LEN.saturating_sub(prefix.len() + suffix.len());
    format!(
        "{prefix}{}{suffix}",
        utils::readable_name_segment(plan_name, budget)
    )
}

/// Creates a Kubernetes secret that contains an inventory.yml, a playbook.yml, the operator's
/// recap callback plugin, and any static-variables*.yaml for a given PlaybookPlan so that the
/// playbook can be executed afterwards. The workspace is host-agnostic.
///
/// # Panics
///
/// Panics if the playbookplan does not have a namespace, name or uid
///
pub fn render_secret(
    object: &PlaybookPlan,
    target_groups: &[ResolvedInventoryGroup],
    managed_ssh_hosts: &BTreeMap<String, ansible::ManagedSshHostInfo>,
) -> Result<Secret, ReconcileError> {
    let pb_namespace = object
        .metadata
        .namespace
        .as_ref()
        .expect(".metdata.namespace must be set at this point");

    let pb_name = object
        .metadata
        .name
        .as_ref()
        .expect(".metdata.name must be set at this point");

    let pb_uid = object
        .metadata
        .uid
        .as_ref()
        .expect(".metdata.uid must be set at this point");

    let mut secret = Secret::default();

    secret.metadata.namespace = Some(pb_namespace.into());
    secret.metadata.name = Some(workspace_secret_name(pb_name, pb_uid));

    secret.metadata.owner_references = Some(vec![OwnerReference {
        api_version: PlaybookPlan::api_version(&()).into(),
        kind: PlaybookPlan::kind(&()).into(),
        name: pb_name.into(),
        uid: pb_uid.into(),
        ..Default::default()
    }]);

    let rendered_playbook = ansible::render_playbook(&object.spec)?;

    let managed_ssh_client_key_path = paths::managed_ssh_client_key_path();
    let managed_ssh_known_hosts_path = paths::managed_ssh_known_hosts_path();
    let ssh_paths_by_static_inventory = build_ssh_paths_map(target_groups);

    let render_ctx = ansible::RenderContext {
        managed_ssh_hosts,
        managed_ssh_client_key_path: &managed_ssh_client_key_path,
        managed_ssh_known_hosts_path: &managed_ssh_known_hosts_path,
        ssh_paths_by_static_inventory: &ssh_paths_by_static_inventory,
    };
    let rendered_inventory = ansible::render_inventory(target_groups, &render_ctx)?;

    let inlined_variables = match &object.spec.template.variables {
        Some(variable_sources) => variable_sources
            .iter()
            .filter_map(|source| match source {
                crate::v1beta1::PlaybookVariableSource::SecretRef { secret_ref: _ } => None,
                crate::v1beta1::PlaybookVariableSource::Inline { inline } => Some(inline),
            })
            .map(serde_yaml::to_string)
            .collect(),
        None => Vec::new(),
    };

    let mut string_data = BTreeMap::new();
    string_data.insert("playbook.yml".into(), rendered_playbook);
    string_data.insert("inventory.yml".into(), rendered_inventory);
    // Filename must stay exactly `ansible_operator_recap.py` — Ansible's `ANSIBLE_CALLBACKS_ENABLED`
    // matches local/adjacent plugins by filename, not CALLBACK_NAME, and must match the env var
    // set in `job_builder::configure_job_for_callback_plugin`.
    string_data.insert(
        "ansible_operator_recap.py".into(),
        include_str!("../../ansible/ansible_operator_recap.py").to_string(),
    );

    // The preflight gate and the endpoints it waits on travel as workspace *data*, not as arguments
    // in the Job spec, because `job_builder::create_job_blueprint` must stay a pure function of the
    // plan: a resumed `Launching` run rebuilds the blueprint and would otherwise bake in whatever
    // proxy IPs happened to be current at rebuild time.
    if !managed_ssh_hosts.is_empty() {
        string_data.insert(
            paths::MANAGED_SSH_PREFLIGHT_SCRIPT_FILENAME.into(),
            include_str!("../../ansible/ansible_operator_preflight.py").to_string(),
        );
        string_data.insert(
            paths::MANAGED_SSH_PREFLIGHT_ENDPOINTS_FILENAME.into(),
            render_preflight_endpoints(managed_ssh_hosts),
        );
    }

    if let Some(requirements) = &object.spec.template.requirements {
        string_data.insert("requirements.yml".into(), requirements.to_owned());
    }

    for (index, variable_set) in inlined_variables.into_iter().enumerate() {
        string_data.insert(format!("static-variables-{index}.yml"), variable_set?);
    }

    secret.string_data = Some(string_data);

    Ok(secret)
}

/// One `host<TAB>ip<TAB>port` line per proxy the preflight gate should wait for.
///
/// Hosts whose proxy never became Ready are left out on purpose: their `pod_ip` is the unroutable
/// sentinel, so waiting on them could only ever burn the gate's whole budget and delay the hosts
/// that can be rescued. Ansible still records them `unreachable` from the inventory, unchanged.
fn render_preflight_endpoints(hosts: &BTreeMap<String, ansible::ManagedSshHostInfo>) -> String {
    hosts
        .iter()
        .filter(|(_, info)| !info.unreachable)
        .map(|(host, info)| format!("{host}\t{}\t{}\n", info.pod_ip, info.port))
        .collect()
}

/// `StaticInventory` resource name -> (private key mount path, known_hosts mount path), for
/// every distinct `StaticInventory` this run's groups reference.
fn build_ssh_paths_map(groups: &[ResolvedInventoryGroup]) -> BTreeMap<String, (String, String)> {
    let mut map = BTreeMap::new();

    for group in groups {
        if let ResolvedInventoryGroup::Ssh {
            static_inventory_name,
            ..
        } = group
        {
            map.entry(static_inventory_name.clone()).or_insert_with(|| {
                (
                    paths::static_inventory_ssh_key_path(static_inventory_name),
                    paths::static_inventory_known_hosts_path(static_inventory_name),
                )
            });
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::v1beta1::{PlaybookPlan, ansible, controllers::playbookplancontroller::paths};

    fn plan() -> PlaybookPlan {
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

    fn host(pod_ip: &str, unreachable: bool) -> ansible::ManagedSshHostInfo {
        ansible::ManagedSshHostInfo {
            pod_ip: pod_ip.into(),
            port: 22,
            unreachable,
        }
    }

    /// Waiting on a host whose proxy never came up could only ever spend the gate's entire budget
    /// on a dial that cannot succeed, delaying the hosts that are still recoverable.
    #[test]
    fn preflight_endpoints_list_only_the_proxies_that_can_answer() {
        let hosts = BTreeMap::from([
            ("node-a".to_string(), host("10.0.0.1", false)),
            ("node-b".to_string(), host("192.0.2.1", true)),
            ("node-c".to_string(), host("10.0.0.3", false)),
        ]);

        assert_eq!(
            super::render_preflight_endpoints(&hosts),
            "node-a\t10.0.0.1\t22\nnode-c\t10.0.0.3\t22\n"
        );
    }

    #[test]
    fn a_managed_ssh_workspace_carries_the_preflight_gate_and_its_endpoints() {
        let hosts = BTreeMap::from([("node-a".to_string(), host("10.0.0.1", false))]);

        let secret = super::render_secret(&plan(), &[], &hosts).unwrap();
        let data = secret.string_data.unwrap();

        assert_eq!(
            data.get(paths::MANAGED_SSH_PREFLIGHT_ENDPOINTS_FILENAME)
                .map(String::as_str),
            Some("node-a\t10.0.0.1\t22\n")
        );
        assert!(
            data.get(paths::MANAGED_SSH_PREFLIGHT_SCRIPT_FILENAME)
                .is_some_and(|script| script.contains("BANNER_PREFIX"))
        );
    }

    /// The name a user is most likely to have taken is the plan's own — one Secret named after the
    /// plan it feeds. Writing the workspace there overwrites their keys, adopts their object, and,
    /// once the plan references it, moves the execution hash on every write, so a successful run is
    /// replaced forever.
    #[test]
    fn the_workspace_is_not_named_after_the_plan() {
        let secret = super::render_secret(&plan(), &[], &BTreeMap::new()).unwrap();

        assert_ne!(secret.metadata.name.as_deref(), Some("an-example"));
        assert_eq!(
            secret.metadata.name,
            Some(super::workspace_secret_name(
                "an-example",
                "11111111-1111-1111-1111-111111111111"
            ))
        );
    }

    /// A resumed run rebuilds its Job blueprint from the live plan, so the name the workspace is
    /// written under and the one the Job mounts have to agree across ticks, revisions and restarts.
    /// Only the plan's identity may feed it — never its inputs.
    #[test]
    fn the_workspace_name_is_stable_for_a_plan_and_distinct_between_plans() {
        assert_eq!(
            super::workspace_secret_name("web", "uid-1"),
            super::workspace_secret_name("web", "uid-1")
        );

        // A plan deleted and recreated under its own name is a different plan, and must not inherit
        // the workspace its predecessor left behind.
        assert_ne!(
            super::workspace_secret_name("web", "uid-1"),
            super::workspace_secret_name("web", "uid-2")
        );

        // Truncation makes the readable half lossy, so the short id is what keeps two plans whose
        // names agree past the cut apart.
        let shared_prefix = "a".repeat(crate::utils::MAX_DNS_SUBDOMAIN_LEN - 4);
        assert_ne!(
            super::workspace_secret_name(&format!("{shared_prefix}-one"), "uid-1"),
            super::workspace_secret_name(&format!("{shared_prefix}-two"), "uid-2")
        );
    }

    /// A Secret name is a DNS subdomain, but the workspace name is built from a *label*-sized budget
    /// and must stay a valid label on its own — a plan name is a subdomain, so it can be far longer
    /// than the result and may contain dots that truncation could land on. A name only the apiserver
    /// rejects would strand every run of the plan.
    #[test]
    fn the_workspace_name_stays_a_valid_dns_label_however_the_plan_is_named() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN};

        let is_dns_label = |name: &str| {
            !name.is_empty()
                && name.len() <= MAX_DNS_LABEL_LEN
                && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && name.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };

        assert!(is_dns_label(&super::workspace_secret_name(
            &"a".repeat(MAX_DNS_SUBDOMAIN_LEN),
            "plan-uid"
        )));

        // Sweep every truncation point across a dotted name, so whichever one lands on (or just
        // after) a dot is covered rather than guessed at.
        for length in 1..=MAX_DNS_LABEL_LEN + 8 {
            let plan_name: String = (0..length)
                .map(|n| if n % 8 == 7 { '.' } else { 'a' })
                .collect();
            let plan_name = plan_name.trim_end_matches('.');
            if plan_name.is_empty() {
                continue;
            }

            let name = super::workspace_secret_name(plan_name, "plan-uid");
            assert!(
                is_dns_label(&name),
                "workspace name {name:?} is not a label"
            );
        }

        // A name that already fits keeps the readable shape somebody reading `kubectl get secret`
        // needs to recognize it by.
        assert!(super::workspace_secret_name("web", "plan-uid").starts_with("workspace-web-"));
    }

    #[test]
    fn a_workspace_without_managed_ssh_hosts_carries_no_preflight_gate() {
        let secret = super::render_secret(&plan(), &[], &BTreeMap::new()).unwrap();
        let data = secret.string_data.unwrap();

        assert!(!data.contains_key(paths::MANAGED_SSH_PREFLIGHT_SCRIPT_FILENAME));
        assert!(!data.contains_key(paths::MANAGED_SSH_PREFLIGHT_ENDPOINTS_FILENAME));
    }
}
