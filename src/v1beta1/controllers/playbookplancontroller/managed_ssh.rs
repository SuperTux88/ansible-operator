use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        core::v1::{
            Capabilities, Container, HostPathVolumeSource, Node, Pod, PodSpec, Probe, Secret,
            SecurityContext, TCPSocketAction, Volume, VolumeMount,
        },
        networking::v1::{
            NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
            NetworkPolicyPort, NetworkPolicySpec,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::{
    Api,
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams},
};

use super::paths;
use crate::v1beta1::{
    ca::CertificateAuthority,
    controllers::{
        playbookplancontroller::execution_evaluator::ExecutionHash,
        reconcile_error::{ReconcileError, is_not_found},
    },
    labels,
    resources::Toleration,
};

pub const PROXY_SSH_PORT: i32 = 22;

const SSHD_CONFIG_MOUNT_PATH: &str = "/etc/ansible-operator-sshd";
const HOST_KEY_FILENAME: &str = "ssh_host_ed25519_key";
const HOST_CERT_FILENAME: &str = "ssh_host_ed25519_key-cert.pub";
const CA_PUB_FILENAME: &str = "ca.pub";
const ENTER_HOST_SCRIPT_FILENAME: &str = "enter-host.sh";

/// Per-attempt principals file for sshd's `AuthorizedPrincipalsFile`. It contains **only this run's
/// run ID** (see `build_secret`) — never `root`. That scopes the proxy to certs carrying
/// that attempt's principal, so a leaked/strayed client cert from another run is rejected at the
/// sshd cert-principal layer, not just by the per-run NetworkPolicy (THREAT_MODEL R3 / T-INFO-3).
const AUTHORIZED_PRINCIPALS_FILENAME: &str = "authorized_principals";

/// Placeholder value for the `Subsystem sftp` directive, never executed as a binary. Without a
/// `Subsystem sftp` line, sshd rejects sftp requests before `ForceCommand` ever runs; declaring
/// one (even a nonsense one) is what makes sshd hand the request to `ForceCommand` instead, which
/// checks `$SSH_ORIGINAL_COMMAND` against this marker in `render_enter_host_script`.
const SFTP_SUBSYSTEM_MARKER: &str = "ansible-operator-sftp";

/// Where the host's real `/proc` is bind-mounted inside the proxy pod. The pod runs with ordinary
/// pod networking (no `hostNetwork`/`hostIPC`/`privileged`), so sshd binds port 22 in its own
/// namespace rather than colliding with the node's real sshd; each *session* instead nsenters into
/// the host's mount/net/ipc/uts namespaces via `/host/proc/1/ns/*` — see
/// `render_enter_host_script`. This also keeps the NetworkPolicy in `build_network_policy`
/// enforceable, since most CNIs don't apply NetworkPolicy to `hostNetwork` pods.
///
/// `hostPID` is still required though: `setns(CLONE_NEWPID)` can only move to a *descendant* PID
/// namespace, never the host's (an ancestor), so a session can't join it via nsenter — the pod's
/// PID namespace has to start out as the host's.
const HOST_PROC_MOUNT_PATH: &str = "/host/proc";

/// Unroutable stand-in `ansible_host` for a node whose proxy pod never became Ready in time (so it
/// has no pod IP). `192.0.2.1` is RFC 5737 TEST-NET-1, a documentation range that never routes — the
/// SSH dial to it is certain to fail, which is exactly what makes Ansible record the host
/// `unreachable`. Rendered with a short connect timeout (see `inventory_renderer`).
pub const UNREACHABLE_SENTINEL_IP: &str = "192.0.2.1";

/// The two taints Kubernetes automatically applies to a `NotReady`/unreachable Node. We tolerate
/// them with an **empty `effect`** (matches every effect, i.e. both `NoSchedule` and `NoExecute`) and
/// no `tolerationSeconds`, so a managed-ssh proxy pod created *after* a node is already `NotReady` can
/// still be scheduled onto it (the `NoSchedule` variant gates that) and isn't evicted from it.
const NODE_NOT_READY_TAINT: &str = "node.kubernetes.io/not-ready";
const NODE_UNREACHABLE_TAINT: &str = "node.kubernetes.io/unreachable";

/// How long the operator waits for a proxy pod stuck *before* `Running` to become Ready, scaled by
/// how stale the target Node's `Ready`-condition heartbeat is. Built from operator config at startup
/// (see `config::ManagedSshConfig`); seconds throughout.
#[derive(Debug, Clone)]
pub struct ProxyGracePolicy {
    /// The full (tier-0) wait for a recently-alive node.
    pub grace_seconds: i64,
    /// The wait is divided by this at each successive tier; clamped to `>= 1` so it never divides by
    /// zero. Tier `k`'s wait is `grace_seconds / aggressiveness^k`.
    pub aggressiveness: u32,
    /// Three ascending heartbeat-age boundaries (seconds). Past the last one the wait is `0`.
    pub threshold_secs: [i64; 3],
}

impl ProxyGracePolicy {
    /// Builds a policy from raw config: converts the day-thresholds to seconds and clamps
    /// `aggressiveness` to `>= 1` (a `0` would divide by zero at tier >= 1).
    pub fn new(grace_seconds: i64, aggressiveness: u32, threshold_days: [i64; 3]) -> Self {
        Self {
            grace_seconds,
            aggressiveness: aggressiveness.max(1),
            threshold_secs: threshold_days.map(|d| d.saturating_mul(86_400)),
        }
    }
}

pub struct ProxyPodInfo {
    pub host: String,
    pub pod_ip: String,
    pub port: i32,
}

pub enum ProxyReadiness {
    /// Every proxy pod has settled: `ready` carries the reachable hosts (with a live pod IP);
    /// `unreachable` names hosts whose pod never became Ready within its grace window.
    Ready {
        ready: Vec<ProxyPodInfo>,
        unreachable: Vec<String>,
    },
    /// At least one proxy pod is still `Running`-not-yet-Ready or within its startup/termination
    /// grace window; `waiting` names them so the caller can report them on the plan.
    Pending { waiting: Vec<String> },
}

/// Discards the half-built proxy infrastructure of a run that is being resumed after the CA rotated,
/// so `ensure_proxy_infra` rebuilds it against the current CA instead of adopting credentials nobody
/// can authenticate against any more. The CA is in-memory (INV-6), so every operator restart rotates
/// it — which is exactly when a run gets resumed.
///
/// Scoped entirely to this attempt: every name derives from `run_id`, so it can never touch another
/// run's resources.
///
/// **Two things here are load-bearing and must not be "tidied":**
///
/// 1. *The client-cert Secret is the gate, and is deleted last.* Its presence-and-staleness is the
///    only signal that a reset is owed, so it has to outlive every delete that can fail. An
///    interrupted reset therefore leaves the gate open and the next tick re-enters and finishes the
///    job. Deleting it first (or folding it into the loop) would make an interrupted reset look
///    complete, leaving stale per-host Secrets that `ensure_proxy_infra` happily adopts — the run
///    then wedges with old-CA host certificates and a new-CA client certificate.
/// 2. *Returning early when the Secret already trusts the current CA.* That is what makes this
///    idempotent and free on the overwhelmingly common path (a resume within one operator lifetime).
///
/// Deleting a pod only *starts* its termination; see `proxy_pod_readiness`, which refuses to adopt a
/// pod still carrying a deletion timestamp, so the rebuild waits for the old pod to actually go away.
pub async fn reset_incomplete_run(
    client: &kube::Client,
    operator_namespace: &str,
    job_namespace: &str,
    run_id: &str,
    hosts: &[String],
    ca: &CertificateAuthority,
) -> Result<(), ReconcileError> {
    let job_secrets_api = Api::<Secret>::namespaced(client.clone(), job_namespace);
    let client_secret_name = client_cert_secret_name(run_id);
    let Some(client_secret) = job_secrets_api.get_opt(&client_secret_name).await? else {
        return Ok(());
    };
    let current_ca = ca.public_key_openssh()?;
    let trusts_current_ca = client_secret
        .data
        .as_ref()
        .and_then(|data| data.get(paths::MANAGED_SSH_KNOWN_HOSTS_FILENAME))
        .and_then(|value| std::str::from_utf8(&value.0).ok())
        .is_some_and(|known_hosts| known_hosts.contains(&current_ca));
    if trusts_current_ca {
        return Ok(());
    }

    let pods_api = Api::<Pod>::namespaced(client.clone(), operator_namespace);
    let secrets_api = Api::<Secret>::namespaced(client.clone(), operator_namespace);
    for host in hosts {
        let name = resource_name(host, run_id);
        delete_if_exists(&pods_api, &name, &DeleteParams::default()).await?;
        delete_if_exists(&secrets_api, &name, &DeleteParams::default()).await?;
    }
    // Last, deliberately: this Secret is the gate that brought us here, so it must outlive every
    // delete above for an interrupted reset to be retried rather than looking finished. See the
    // doc comment.
    delete_if_exists(
        &job_secrets_api,
        &client_secret_name,
        &DeleteParams::default(),
    )
    .await
}

/// A proxy pod's k8s state as far as the readiness gate cares: Ready (with its pod IP), still
/// `Running` (waited on indefinitely), stuck before `Running` (subject to the grace window), or
/// `Terminating` (a deleted pod that has not disappeared yet, also subject to the grace window).
#[derive(Debug, PartialEq)]
enum PodReadyState {
    ReadyWithIp(String),
    Running,
    PreRunning,
    Terminating,
}

/// Pure classification of a proxy pod. A pod carrying a `deletionTimestamp` ⇒ `Terminating`, checked
/// *first* and deliberately ahead of the Ready condition: pod deletion is graceful and asynchronous,
/// so a doomed pod keeps `phase: Running`, `Ready=True` and a live pod IP for its whole termination
/// grace period. `reset_incomplete_run` deletes this run's pods and immediately re-enters
/// `ensure_proxy_infra` in the same tick, so without this check the run would adopt a corpse still
/// serving the *previous* CA's host certificate — and, because it looks Ready, sail straight through
/// the readiness gate and launch the Job against it (every session then failing
/// `Permission denied (publickey)`). Treating it as not-yet-ready instead makes the tick wait until
/// the object is really gone, at which point the pod is recreated against the current CA.
///
/// Otherwise: Ready-condition `True` + a pod IP ⇒ `ReadyWithIp`; else a pod that has reached
/// `Running` ⇒ `Running` (sshd still coming up — waited on with no timeout, as before); anything
/// earlier (`Pending`/`Unknown`/absent phase) ⇒ `PreRunning`.
fn proxy_pod_readiness(pod: &Pod) -> PodReadyState {
    if pod.metadata.deletion_timestamp.is_some() {
        return PodReadyState::Terminating;
    }

    let status = pod.status.as_ref();
    let ready = status
        .and_then(|s| s.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false);
    let pod_ip = status.and_then(|s| s.pod_ip.clone());

    if let (true, Some(ip)) = (ready, pod_ip) {
        return PodReadyState::ReadyWithIp(ip);
    }

    match status.and_then(|s| s.phase.as_deref()) {
        Some("Running") => PodReadyState::Running,
        _ => PodReadyState::PreRunning,
    }
}

/// Seconds since the Node's `Ready` condition last reported (`lastHeartbeatTime`) — a proxy for how
/// long the node has been silent. `None` if the node/condition/timestamp is missing, which the caller
/// treats conservatively (full grace).
fn node_ready_heartbeat_age_secs(node: &Node, now_epoch_secs: i64) -> Option<i64> {
    let ready = node
        .status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == "Ready")?;
    let last = ready.last_heartbeat_time.as_ref()?;
    Some(now_epoch_secs - last.0.as_second())
}

/// The effective grace for a pre-`Running` or terminating pod: `grace_seconds / aggressiveness^k`
/// for the first tier `k` whose boundary the heartbeat age falls within, `0` past the last boundary.
/// An unknown age means full grace (never shorten on missing data). A healthy node's heartbeat is
/// always recent, so it always lands in tier 0.
fn effective_grace_secs(heartbeat_age_secs: Option<i64>, policy: &ProxyGracePolicy) -> i64 {
    let Some(age) = heartbeat_age_secs else {
        return policy.grace_seconds;
    };
    for (k, &threshold) in policy.threshold_secs.iter().enumerate() {
        if age <= threshold {
            let divisor = (policy.aggressiveness as i64).saturating_pow(k as u32);
            return policy.grace_seconds / divisor;
        }
    }
    0
}

fn proxy_wait_age_secs(pod: &Pod, state: &PodReadyState, now_epoch_secs: i64) -> Option<i64> {
    let started = match state {
        PodReadyState::Terminating => pod.metadata.deletion_timestamp.as_ref(),
        PodReadyState::PreRunning => pod.metadata.creation_timestamp.as_ref(),
        PodReadyState::ReadyWithIp(_) | PodReadyState::Running => None,
    }?;
    Some(now_epoch_secs - started.0.as_second())
}

/// Node taints Kubernetes auto-applies to a `NotReady` node tolerated by every proxy pod, merged with
/// any user `spec.tolerations`. A user toleration for the same key wins (we skip our default for it).
/// See [`NODE_NOT_READY_TAINT`] for why the effect is left empty.
fn merge_default_tolerations(
    user: Option<&[Toleration]>,
) -> Vec<k8s_openapi::api::core::v1::Toleration> {
    let mut merged: Vec<k8s_openapi::api::core::v1::Toleration> = user
        .map(|ts| ts.iter().map(|t| t.clone().into()).collect())
        .unwrap_or_default();

    let existing_keys: std::collections::BTreeSet<String> =
        merged.iter().filter_map(|t| t.key.clone()).collect();

    for key in [NODE_NOT_READY_TAINT, NODE_UNREACHABLE_TAINT] {
        if !existing_keys.contains(key) {
            merged.push(k8s_openapi::api::core::v1::Toleration {
                key: Some(key.to_string()),
                operator: Some("Exists".to_string()),
                effect: None,
                value: None,
                toleration_seconds: None,
            });
        }
    }

    merged
}

/// Deterministic, human-readable resource name for a (host, attempt) pair. The host is used verbatim
/// (not hashed) since managed-ssh only targets `ClusterInventory` hosts, i.e. real Node names,
/// which are already valid Kubernetes object name components. The attempt is identified by its run
/// ID, so a delayed cleanup can never reach a retry's pods.
///
/// Length budget, since nothing truncates here: the result names a Pod and a Secret, so it is bounded
/// by `utils::MAX_DNS_SUBDOMAIN_LEN`. The host is separately bounded to `utils::MAX_DNS_LABEL_LEN`
/// because it is also written as the `PLAYBOOKPLAN_HOST` **label value** (`run_labels`) — so the
/// worst case is 13 + 63 + 1 + `reconciler::RUN_ID_LENGTH`, leaving well over 150 characters of
/// headroom. A test pins that, so growing the run ID (or ever sourcing the host from something
/// unlabelled) fails there rather than at the apiserver.
fn resource_name(host: &str, run_id: &str) -> String {
    format!("ansible-sshd-{host}-{run_id}")
}

/// Name of this run's client-cert Secret, shared by `job_builder`'s mount and `ensure_client_cert`.
pub fn client_cert_secret_name(run_id: &str) -> String {
    format!("managed-ssh-client-{run_id}")
}

fn run_labels(
    execution_hash: &ExecutionHash,
    run_id: &str,
    host: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            labels::PLAYBOOKPLAN_HASH.to_string(),
            execution_hash.to_string(),
        ),
        (labels::RUN_ID.to_string(), run_id.to_string()),
        (labels::PLAYBOOKPLAN_HOST.to_string(), host.to_string()),
        (
            labels::COMPONENT.to_string(),
            labels::MANAGED_SSH_PROXY_COMPONENT.to_string(),
        ),
    ])
}

/// `ForceCommand` routes every session through `enter-host.sh` rather than `ChrootDirectory` —
/// nsenter-ing the host's mount namespace already makes `/` the host's real root, so no chroot
/// step is needed. `UsePAM` is omitted: some minimal sshd builds reject it outright (no PAM
/// support), and auth here is pubkey/cert-only anyway.
///
/// `StrictModes no` is **required**, not cosmetic: the `AuthorizedPrincipalsFile` is the only file
/// here that sshd runs through its `secure_filename` ownership/permission gate (the host key, host
/// cert, ca.pub and this config are loaded directly and skip it). In-cluster those files live in a
/// Kubernetes Secret mount — a tmpfs whose `..data/`-symlinked path and directory modes
/// `secure_filename` refuses under the default `StrictModes yes`. sshd then silently *discards* the
/// principals file, so no cert principal ever matches and every login fails with
/// `Permission denied (publickey)`. Disabling StrictModes does not weaken isolation: the per-run
/// run-ID principal check still runs (INV-4 / T-INFO-3); only the file-permission gate is skipped,
/// and every file in the mount is operator-rendered and read-only.
fn render_sshd_config() -> String {
    format!(
        "Port {PROXY_SSH_PORT}\n\
         HostKey {SSHD_CONFIG_MOUNT_PATH}/{HOST_KEY_FILENAME}\n\
         HostCertificate {SSHD_CONFIG_MOUNT_PATH}/{HOST_CERT_FILENAME}\n\
         TrustedUserCAKeys {SSHD_CONFIG_MOUNT_PATH}/{CA_PUB_FILENAME}\n\
         StrictModes no\n\
         AuthorizedPrincipalsFile {SSHD_CONFIG_MOUNT_PATH}/{AUTHORIZED_PRINCIPALS_FILENAME}\n\
         ForceCommand {SSHD_CONFIG_MOUNT_PATH}/{ENTER_HOST_SCRIPT_FILENAME}\n\
         PermitRootLogin yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         Subsystem sftp {SFTP_SUBSYSTEM_MARKER}\n"
    )
}

/// Wraps every SSH session in an `nsenter` into the host's mount/net/ipc/uts namespaces via the
/// bind-mounted `/host/proc/1/ns/*`. Requires `CAP_SYS_ADMIN`/`CAP_SYS_PTRACE` on the container
/// (see `build_pod`'s `SecurityContext`), not `privileged: true`.
///
/// No `-p`/pid join: `setns(CLONE_NEWPID)` can only move to a descendant PID namespace, never the
/// host's (an ancestor); `build_pod` sets `hostPID: true` instead.
///
/// Flags use the glued short-option form (`-m"$NS/mnt"`, no `=`) rather than `--mount=` — BusyBox's
/// `nsenter` (shipped by the first-party proxy image) doesn't parse the long form at all and fails
/// silently. The glued short form also works against genuine util-linux `nsenter`, so a custom proxy
/// image built with either flavour is fine.
///
/// Special-cases sftp: `ForceCommand` overrides `Subsystem sftp` requests the same way it does
/// shell/exec, setting `$SSH_ORIGINAL_COMMAND` to `SFTP_SUBSYSTEM_MARKER`. Since there's no
/// portable path for the `sftp-server` binary across distros, this tries the common ones on the
/// target host's filesystem and execs whichever exists.
fn render_enter_host_script() -> String {
    format!(
        "#!/bin/sh\n\
         set -e\n\
         NS={HOST_PROC_MOUNT_PATH}/1/ns\n\
         if [ \"$SSH_ORIGINAL_COMMAND\" = \"{SFTP_SUBSYSTEM_MARKER}\" ]; then\n\
         \texec nsenter -m\"$NS/mnt\" -n\"$NS/net\" -i\"$NS/ipc\" -u\"$NS/uts\" -- sh -c '\n\
         \t\tfor c in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/lib/misc/sftp-server /usr/lib64/misc/sftp-server /usr/lib64/openssh/sftp-server; do\n\
         \t\t\t[ -x \"$c\" ] && exec \"$c\"\n\
         \t\tdone\n\
         \t\techo \"no sftp-server binary found on target host\" >&2\n\
         \t\texit 1\n\
         \t'\n\
         elif [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then\n\
         \texec nsenter -m\"$NS/mnt\" -n\"$NS/net\" -i\"$NS/ipc\" -u\"$NS/uts\" -- sh -c \"$SSH_ORIGINAL_COMMAND\"\n\
         else\n\
         \texec nsenter -m\"$NS/mnt\" -n\"$NS/net\" -i\"$NS/ipc\" -u\"$NS/uts\" -- sh\n\
         fi\n"
    )
}

/// Builds the per-host Secret carrying the proxy pod's sshd host key/cert (generated by the
/// operator, not the pod, so there's no need to wait for a key to be reported back), the CA
/// public key, the rendered sshd_config, and the nsenter entry script.
fn build_secret(
    name: &str,
    execution_hash: &ExecutionHash,
    run_id: &str,
    host: &str,
    ca: &CertificateAuthority,
) -> Result<Secret, ReconcileError> {
    let host_key = crate::v1beta1::ca::generate_ephemeral_keypair()?;
    let host_cert = ca.sign_host_cert(host_key.public_key(), host)?;
    let ca_pub = ca.public_key_openssh()?;

    let host_key_openssh = host_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(crate::v1beta1::ca::CaError::from)?
        .to_string();

    let mut string_data = BTreeMap::new();
    string_data.insert(HOST_KEY_FILENAME.to_string(), host_key_openssh);
    string_data.insert(HOST_CERT_FILENAME.to_string(), host_cert);
    string_data.insert(CA_PUB_FILENAME.to_string(), ca_pub);
    // ONLY this attempt's run ID — never "root". This is the sole principal sshd's
    // `AuthorizedPrincipalsFile` will accept, so a client cert from any other attempt (whose run ID
    // differs, even for a retry of the same execution hash) is rejected even if it can reach this
    // pod. Must match the run-ID principal minted in `ensure_client_cert`.
    string_data.insert(
        AUTHORIZED_PRINCIPALS_FILENAME.to_string(),
        format!("{run_id}\n"),
    );
    string_data.insert("sshd_config".to_string(), render_sshd_config());
    string_data.insert(
        ENTER_HOST_SCRIPT_FILENAME.to_string(),
        render_enter_host_script(),
    );

    Ok(Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(run_labels(execution_hash, run_id, host)),
            ..Default::default()
        },
        string_data: Some(string_data),
        ..Default::default()
    })
}

fn build_pod(
    name: &str,
    secret_name: &str,
    execution_hash: &ExecutionHash,
    run_id: &str,
    host: &str,
    tolerations: Option<&[Toleration]>,
    proxy_image: &str,
) -> Pod {
    let secret_volume = Volume {
        name: "sshd-config".into(),
        secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
            secret_name: Some(secret_name.to_string()),
            // 0500 not 0400 — the entry script needs to be executable; sshd's host-key
            // permission check only cares about group/world access, which stays closed.
            default_mode: Some(0o0500),
            ..Default::default()
        }),
        ..Default::default()
    };

    let host_proc_volume = Volume {
        name: "host-proc".into(),
        host_path: Some(HostPathVolumeSource {
            type_: Some("Directory".into()),
            path: "/proc".into(),
        }),
        ..Default::default()
    };

    let container = Container {
        name: "sshd".into(),
        image: Some(proxy_image.into()),
        command: Some(vec![
            "/usr/sbin/sshd".into(),
            "-D".into(),
            "-e".into(),
            "-f".into(),
            format!("{SSHD_CONFIG_MOUNT_PATH}/sshd_config"),
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "sshd-config".into(),
                mount_path: SSHD_CONFIG_MOUNT_PATH.into(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "host-proc".into(),
                mount_path: HOST_PROC_MOUNT_PATH.into(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            // Not `privileged: true` — only the two capabilities nsenter needs.
            capabilities: Some(Capabilities {
                add: Some(vec!["SYS_ADMIN".into(), "SYS_PTRACE".into()]),
                ..Default::default()
            }),
            // nsenter-ing the host's mount namespace doesn't change the process's SELinux label
            // (stays `container_t`, denied host filesystem access). `spc_t` is the same label
            // `privileged: true` pods and `oc debug node/...` get, and is what actually allows
            // host filesystem access. No-op on non-SELinux nodes.
            se_linux_options: Some(k8s_openapi::api::core::v1::SELinuxOptions {
                type_: Some("spc_t".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(PROXY_SSH_PORT),
                ..Default::default()
            }),
            period_seconds: Some(2),
            ..Default::default()
        }),
        ..Default::default()
    };

    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(run_labels(execution_hash, run_id, host)),
            ..Default::default()
        },
        spec: Some(PodSpec {
            containers: vec![container],
            automount_service_account_token: Some(false),
            volumes: Some(vec![secret_volume, host_proc_volume]),
            restart_policy: Some("Never".into()),
            // Required: unlike the other host namespaces, PID can't be joined per-session via
            // nsenter (see HOST_PROC_MOUNT_PATH doc), so it must be shared from pod creation.
            host_pid: Some(true),
            node_selector: Some(BTreeMap::from([(
                "kubernetes.io/hostname".into(),
                host.into(),
            )])),
            // Always tolerate the NotReady/unreachable taints (merged with the user's), so the proxy
            // pod still schedules onto a NotReady node — see `merge_default_tolerations`.
            tolerations: Some(merge_default_tolerations(tolerations)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// NetworkPolicy restricting ingress on this run's proxy pods to only the ansible Job pod for
/// this run. Needs both a podSelector and a namespaceSelector (via `kubernetes.io/metadata.name`)
/// since the policy lives in the operator's namespace but the Job pod lives in the plan's —
/// a bare podSelector alone would match nothing. Requires a NetworkPolicy-enforcing CNI.
fn build_network_policy(
    name: &str,
    execution_hash: &ExecutionHash,
    run_id: &str,
    job_namespace: &str,
    egress: Option<Vec<NetworkPolicyEgressRule>>,
) -> NetworkPolicy {
    let mut policy_types = vec!["Ingress".into()];
    if egress.is_some() {
        policy_types.push("Egress".into());
    }
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([
                (
                    labels::PLAYBOOKPLAN_HASH.to_string(),
                    execution_hash.to_string(),
                ),
                (labels::RUN_ID.to_string(), run_id.to_string()),
            ])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([
                    (
                        labels::PLAYBOOKPLAN_HASH.to_string(),
                        execution_hash.to_string(),
                    ),
                    (
                        labels::COMPONENT.to_string(),
                        labels::MANAGED_SSH_PROXY_COMPONENT.to_string(),
                    ),
                    (labels::RUN_ID.to_string(), run_id.to_string()),
                ])),
                ..Default::default()
            }),
            policy_types: Some(policy_types),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "kubernetes.io/metadata.name".to_string(),
                            job_namespace.to_string(),
                        )])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([
                            (
                                labels::PLAYBOOKPLAN_HASH.to_string(),
                                execution_hash.to_string(),
                            ),
                            (
                                labels::COMPONENT.to_string(),
                                labels::PLAYBOOK_COMPONENT.to_string(),
                            ),
                            (labels::RUN_ID.to_string(), run_id.to_string()),
                        ])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(PROXY_SSH_PORT)),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
            }]),
            egress,
        }),
    }
}

/// Renders this run's client-cert files — private key, a cert signed for `["root", <run-id>]`, and
/// the `@cert-authority` known_hosts line — as a `filename -> contents` map. Split out from
/// `ensure_client_cert` (which just wraps this in a Secret) so tests can exercise the exact client
/// material the Job pod mounts against a real sshd, rather than re-deriving it.
///
/// The per-attempt run ID is the *enforced* principal: each proxy's principals file lists only
/// its own run ID, so this cert authenticates only to this attempt's proxies. "root" is kept as a
/// harmless second principal (belt-and-suspenders for sshd's default username check on builds/configs
/// where `AuthorizedPrincipalsFile` isn't in force); `PermitRootLogin yes` authorizes the root login.
fn render_client_cert_files(
    ca: &CertificateAuthority,
    run_id: &str,
) -> Result<BTreeMap<String, String>, ReconcileError> {
    let client_key = crate::v1beta1::ca::generate_ephemeral_keypair()?;
    let client_cert = ca.sign_client_cert(client_key.public_key(), &["root", run_id])?;
    let ca_pub = ca.public_key_openssh()?;

    let client_key_openssh = client_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(crate::v1beta1::ca::CaError::from)?
        .to_string();

    let mut string_data = BTreeMap::new();
    string_data.insert(
        paths::MANAGED_SSH_CLIENT_KEY_FILENAME.to_string(),
        client_key_openssh,
    );
    string_data.insert(
        paths::MANAGED_SSH_CLIENT_CERT_FILENAME.to_string(),
        client_cert,
    );
    string_data.insert(
        paths::MANAGED_SSH_KNOWN_HOSTS_FILENAME.to_string(),
        format!("@cert-authority * {ca_pub}"),
    );

    Ok(string_data)
}

/// Ensures this run's client-cert Secret exists — one client identity trusted by every proxy pod
/// via the CA, not per-host `authorized_keys`. Idempotent.
///
/// `secrets_api` MUST be scoped to the **plan** namespace, not the operator namespace: the ansible
/// Job pod (which lives in the plan namespace) mounts this Secret by name, and a pod can only mount
/// Secrets from its own namespace. The `plan_owner` `OwnerReference` (the PlaybookPlan, same
/// namespace) is the crash-safety backstop — Kubernetes GC reaps the Secret if the plan is deleted
/// before `cleanup_proxy_infra`'s explicit delete runs; the explicit delete is the primary path.
async fn ensure_client_cert(
    secrets_api: &Api<Secret>,
    execution_hash: &ExecutionHash,
    run_id: &str,
    ca: &CertificateAuthority,
    plan_owner: &OwnerReference,
) -> Result<(), ReconcileError> {
    let name = client_cert_secret_name(run_id);

    if secrets_api.get_opt(&name).await?.is_some() {
        return Ok(());
    }

    let string_data = render_client_cert_files(ca, run_id)?;

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name),
            labels: Some(BTreeMap::from([
                (
                    labels::PLAYBOOKPLAN_HASH.to_string(),
                    execution_hash.to_string(),
                ),
                (labels::RUN_ID.to_string(), run_id.to_string()),
            ])),
            owner_references: Some(vec![plan_owner.clone()]),
            ..Default::default()
        },
        string_data: Some(string_data),
        ..Default::default()
    };

    secrets_api.create(&PostParams::default(), &secret).await?;

    Ok(())
}

/// Ensures a proxy pod (+ its Secret + the run's NetworkPolicy) exists and is Ready for every
/// host in `hosts`. Safe to call every reconcile tick — only missing pieces are created.
// Each argument is a distinct, unrelated input (two namespaces, hash, hosts, CA, image, policy,
// owner); bundling them into a struct would only move the noise, so keep them explicit.
#[allow(clippy::too_many_arguments)]
pub async fn ensure_proxy_infra(
    client: &kube::Client,
    operator_namespace: &str,
    job_namespace: &str,
    execution_hash: &ExecutionHash,
    run_id: &str,
    hosts: &[String],
    tolerations: Option<&[Toleration]>,
    grace_policy: &ProxyGracePolicy,
    ca: &CertificateAuthority,
    proxy_image: &str,
    network_policy_egress: Option<Vec<NetworkPolicyEgressRule>>,
    plan_owner: &OwnerReference,
) -> Result<ProxyReadiness, ReconcileError> {
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), operator_namespace);
    let nodes_api: Api<Node> = Api::all(client.clone());
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), operator_namespace);
    let netpol_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), operator_namespace);
    // The client-cert Secret is the one piece of proxy infra that lives in the PLAN namespace, not
    // the operator namespace — the ansible Job pod mounts it, and pods can only mount Secrets from
    // their own namespace. Everything else here (proxy pods, per-host Secrets, NetworkPolicy) stays
    // in the operator namespace.
    let job_secrets_api: Api<Secret> = Api::namespaced(client.clone(), job_namespace);

    if !hosts.is_empty() {
        let netpol_name = format!("managed-ssh-{run_id}");
        let netpol = build_network_policy(
            &netpol_name,
            execution_hash,
            run_id,
            job_namespace,
            network_policy_egress,
        );
        netpol_api
            .patch(
                &netpol_name,
                &PatchParams::apply("ansible-operator").force(),
                &Patch::Apply(&netpol),
            )
            .await?;

        ensure_client_cert(&job_secrets_api, execution_hash, run_id, ca, plan_owner).await?;
    }

    let now = chrono::Utc::now().timestamp();

    let mut ready = Vec::new();
    let mut unreachable = Vec::new();
    let mut waiting = Vec::new();

    for host in hosts {
        let name = resource_name(host, run_id);

        if secrets_api.get_opt(&name).await?.is_none() {
            let secret = build_secret(&name, execution_hash, run_id, host, ca)?;
            secrets_api.create(&PostParams::default(), &secret).await?;
        }

        // Create the pod for EVERY host, including a NotReady one — we want to attempt scheduling it.
        let pod = match pods_api.get_opt(&name).await? {
            Some(pod) => pod,
            None => {
                let pod = build_pod(
                    &name,
                    &name,
                    execution_hash,
                    run_id,
                    host,
                    tolerations,
                    proxy_image,
                );
                pods_api.create(&PostParams::default(), &pod).await?
            }
        };

        match proxy_pod_readiness(&pod) {
            PodReadyState::ReadyWithIp(ip) => ready.push(ProxyPodInfo {
                host: host.clone(),
                pod_ip: ip,
                port: PROXY_SSH_PORT,
            }),
            // Reached Running — sshd is coming up; wait indefinitely, exactly as before (no timeout).
            PodReadyState::Running => waiting.push(host.clone()),
            // A pod stuck before Running or terminating after a reset gets the same
            // heartbeat-scaled deadline. Until then a terminating pod is never adopted; after the
            // deadline the host is rendered unreachable so a dead kubelet cannot wedge this run and
            // its Leases forever.
            state @ (PodReadyState::PreRunning | PodReadyState::Terminating) => {
                let heartbeat_age = match nodes_api.get_opt(host).await? {
                    Some(node) => node_ready_heartbeat_age_secs(&node, now),
                    None => None,
                };
                let grace = effective_grace_secs(heartbeat_age, grace_policy);
                match proxy_wait_age_secs(&pod, &state, now) {
                    Some(age) if age >= grace => unreachable.push(host.clone()),
                    _ => waiting.push(host.clone()),
                }
            }
        }
    }

    Ok(if waiting.is_empty() {
        ProxyReadiness::Ready { ready, unreachable }
    } else {
        ProxyReadiness::Pending { waiting }
    })
}

/// Deletes every resource belonging to this run: the operator-namespace proxy pods, their per-host
/// Secrets and the run's NetworkPolicy via label-scoped `delete_collection`, plus the plan-namespace
/// client-cert Secret by exact name. The operator-ns sweep is by-label so the host list isn't needed
/// — GC-by-label catches everything tagged with the attempt's run ID regardless of how the inventory
/// drifted since the run started. (The CA is in-memory only, not a Secret, so nothing CA-related is
/// in scope here.) The operator-ns resources can't use ownerReferences, since Kubernetes GC ignores
/// references that cross namespaces (they live in the operator namespace, the Job/PlaybookPlan in the
/// plan namespace).
///
/// **Not** best-effort: every delete is propagated, and the caller must not treat a run as released
/// until this returns `Ok`. These are node-root pods and the credentials that reach them, so a
/// partial sweep has to be retried rather than forgotten — the run's `Play` deliberately outlives
/// cleanup so the next reconcile can re-enter here, and every delete is idempotent. The deletes run
/// in sequence and short-circuit on the first error, so a stuck cleanup should be diagnosed from the
/// *first* failing resource, not the last.
///
/// The client-cert Secret is deleted **by name**, not by the hash label: it lives in the plan
/// namespace where the ansible Job and its pod carry that same `PLAYBOOKPLAN_HASH` label, so a
/// label-scoped `delete_collection` there would also sweep them. Its ownerReference on the
/// PlaybookPlan is the backstop if this explicit delete never runs (operator crash / plan deleted
/// mid-run). Deleting it is not the revocation mechanism — that is the deletion of the proxy pods,
/// which happens first and after which the cert authenticates to nothing (INV-4 / T-INFO-3).
///
/// Pods use a tighter selector than the operator-ns Secrets/NetworkPolicy: the ansible Job pod
/// carries the same `PLAYBOOKPLAN_HASH` and `RUN_ID` labels but is NOT proxy infra — it must be
/// reaped by its own Job's `ttlSecondsAfterFinished`, never here. That only collides when the
/// operator and the plan share a namespace, but requiring the per-host `PLAYBOOKPLAN_HOST` label
/// (which only proxy pods carry) excludes the ansible pod cleanly.
pub async fn cleanup_proxy_infra(
    client: &kube::Client,
    operator_namespace: &str,
    job_namespace: &str,
    execution_hash: &ExecutionHash,
    run_id: &str,
    playbookplan_name: &str,
) -> Result<(), ReconcileError> {
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), operator_namespace);
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), operator_namespace);
    let netpol_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), operator_namespace);
    let job_secrets_api: Api<Secret> = Api::namespaced(client.clone(), job_namespace);
    let job_netpol_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), job_namespace);

    let dp = DeleteParams::default();
    let run_selector = format!(
        "{}={execution_hash},{}={run_id}",
        labels::PLAYBOOKPLAN_HASH,
        labels::RUN_ID
    );

    // Existence of PLAYBOOKPLAN_HOST spares the ansible Job pod (which lacks it) — see the doc.
    let pods_lp =
        ListParams::default().labels(&format!("{run_selector},{}", labels::PLAYBOOKPLAN_HOST));
    // Hash + run ID selector: no other attempt shares this cleanup identity.
    let rest_lp = ListParams::default().labels(&run_selector);

    pods_api.delete_collection(&dp, &pods_lp).await?;
    secrets_api.delete_collection(&dp, &rest_lp).await?;
    netpol_api.delete_collection(&dp, &rest_lp).await?;
    delete_if_exists(
        &job_netpol_api,
        &super::job_builder::job_network_policy_name(playbookplan_name, run_id),
        &dp,
    )
    .await?;
    // Plan-namespace client-cert Secret: by name, never by label (would catch the Job/pod). See doc.
    delete_if_exists(&job_secrets_api, &client_cert_secret_name(run_id), &dp).await?;

    Ok(())
}

async fn delete_if_exists<K>(
    api: &Api<K>,
    name: &str,
    params: &DeleteParams,
) -> Result<(), ReconcileError>
where
    K: kube::Resource<DynamicType = ()> + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    match api.delete(name, params).await {
        Ok(_) => Ok(()),
        Err(error) if is_not_found(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the wire format of the per-attempt resource names, and the length budget behind
    /// `resource_name` — see its doc comment for why nothing truncates there.
    #[test]
    fn attempt_scoped_resource_names_keep_their_shape_and_fit() {
        use crate::utils::{MAX_DNS_LABEL_LEN, MAX_DNS_SUBDOMAIN_LEN, generate_id_with_length};
        use crate::v1beta1::controllers::playbookplancontroller::reconciler::RUN_ID_LENGTH;

        assert_eq!(
            resource_name("worker-1", "run-a"),
            "ansible-sshd-worker-1-run-a"
        );
        assert_eq!(client_cert_secret_name("run-a"), "managed-ssh-client-run-a");

        // The host is bounded by the label cap (it is also a label value), the whole name by the
        // subdomain cap (it names a Pod and a Secret).
        let run_id = generate_id_with_length(u64::MAX, RUN_ID_LENGTH);
        let name = resource_name(&"n".repeat(MAX_DNS_LABEL_LEN), &run_id);
        assert!(
            name.len() <= MAX_DNS_SUBDOMAIN_LEN,
            "worst-case proxy resource name is {} characters",
            name.len()
        );
    }

    /// These labels are the cleanup selector's whole contract: `PLAYBOOKPLAN_HOST` is what tells a
    /// proxy pod apart from the ansible Job pod, and `RUN_ID` is what keeps one attempt's sweep off
    /// another's resources.
    #[test]
    fn run_labels_carry_the_hash_run_id_host_and_component() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let labels = run_labels(&hash, "run-1", "worker-1");

        assert_eq!(labels[labels::PLAYBOOKPLAN_HASH], hash.to_string());
        assert_eq!(labels[labels::RUN_ID], "run-1");
        assert_eq!(labels[labels::PLAYBOOKPLAN_HOST], "worker-1");
        assert_eq!(
            labels[labels::COMPONENT],
            labels::MANAGED_SSH_PROXY_COMPONENT
        );
    }

    /// INV-7. The pod sweep and the ansible Job pod both carry `PLAYBOOKPLAN_HASH` *and* `RUN_ID`,
    /// so requiring `PLAYBOOKPLAN_HOST` — which only proxy pods have — is the single thing standing
    /// between `cleanup_proxy_infra`'s `delete_collection` and the Job pod running the playbook.
    /// Deleting that pod mid-run would kill the run it is cleaning up after.
    #[test]
    fn the_proxy_pod_sweep_selector_cannot_match_the_ansible_job_pod() {
        use crate::v1beta1::controllers::playbookplancontroller::{
            execution_evaluator::calculate_execution_hash, job_builder,
        };

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let run_id = "run-1";

        let mut plan =
            crate::v1beta1::PlaybookPlan::new("web", crate::v1beta1::PlaybookPlanSpec::default());
        plan.metadata.namespace = Some("team".into());
        plan.metadata.uid = Some("plan-uid".into());
        let job = job_builder::create_job_blueprint(&hash, 1, run_id, &[], &plan).unwrap();
        let job_pod_labels = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .clone()
            .unwrap();

        // The Job pod does match the hash+run-id part of the selector — that is the whole risk.
        assert_eq!(job_pod_labels[labels::PLAYBOOKPLAN_HASH], hash.to_string());
        assert_eq!(job_pod_labels[labels::RUN_ID], run_id);

        // ...and is spared only because it carries no target-host label.
        assert!(
            !job_pod_labels.contains_key(labels::PLAYBOOKPLAN_HOST),
            "the ansible Job pod must never carry {}, or cleanup would sweep it",
            labels::PLAYBOOKPLAN_HOST
        );

        // A proxy pod, by contrast, is matched by every part of the selector.
        let proxy = build_pod(
            "ansible-sshd-worker-1-run-1",
            "ansible-sshd-worker-1-run-1",
            &hash,
            run_id,
            "worker-1",
            None,
            "proxy:latest",
        );
        let proxy_labels = proxy.metadata.labels.as_ref().unwrap();
        for key in [
            labels::PLAYBOOKPLAN_HASH,
            labels::RUN_ID,
            labels::PLAYBOOKPLAN_HOST,
        ] {
            assert!(proxy_labels.contains_key(key), "proxy pod must carry {key}");
        }
    }

    /// The proxy pod is the node-root primitive, so the privileges it does *and does not* ask for are
    /// part of the threat model rather than an implementation detail (THREAT_MODEL §T-ESC-1).
    #[test]
    fn build_pod_pins_the_node_root_privileges_and_targets_its_own_node() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let pod = build_pod(
            "ansible-sshd-worker-1-run-1",
            "ansible-sshd-worker-1-run-1",
            &hash,
            "run-1",
            "worker-1",
            None,
            "proxy:latest",
        );
        let spec = pod.spec.as_ref().unwrap();

        // Scheduled onto the exact node it proxies — the pod IS the node's access path. Pinned by
        // `nodeSelector` rather than `nodeName` so normal scheduling (taints, tolerations) still
        // applies; see `merge_default_tolerations`.
        assert_eq!(
            spec.node_selector.as_ref().unwrap()["kubernetes.io/hostname"],
            "worker-1"
        );

        // hostPID is required (nsenter needs a host process to enter); the rest must stay off.
        assert_eq!(spec.host_pid, Some(true));
        assert_ne!(spec.host_network, Some(true));
        assert_ne!(spec.host_ipc, Some(true));

        let container = &spec.containers[0];
        assert_eq!(container.image.as_deref(), Some("proxy:latest"));
        let security = container.security_context.as_ref().unwrap();
        assert_ne!(
            security.privileged,
            Some(true),
            "capabilities are granted explicitly, never via blanket privileged"
        );
        let added = security.capabilities.as_ref().unwrap().add.clone().unwrap();
        assert!(added.contains(&"SYS_ADMIN".to_string()));
        assert!(added.contains(&"SYS_PTRACE".to_string()));
    }

    #[test]
    fn proxy_network_policy_adds_egress_only_when_configured() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let ingress_only = build_network_policy("proxy", &hash, "run-1", "plans", None);
        assert_eq!(
            ingress_only.spec.unwrap().policy_types.unwrap(),
            vec!["Ingress"]
        );

        let with_egress = build_network_policy(
            "proxy",
            &hash,
            "run-1",
            "plans",
            Some(vec![NetworkPolicyEgressRule::default()]),
        );
        let spec = with_egress.spec.unwrap();
        assert_eq!(spec.policy_types.unwrap(), vec!["Ingress", "Egress"]);
        assert_eq!(spec.egress.unwrap().len(), 1);
    }

    #[test]
    fn build_secret_writes_the_run_id_as_the_sole_authorized_principal() {
        use crate::v1beta1::ca::CertificateAuthority;
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let ca = CertificateAuthority::generate().unwrap();
        let hash = calculate_execution_hash("playbook-a", std::iter::empty());

        let secret =
            build_secret("ansible-sshd-worker-1-abc", &hash, "run-1", "worker-1", &ca).unwrap();
        let principals = secret
            .string_data
            .as_ref()
            .and_then(|d| d.get(AUTHORIZED_PRINCIPALS_FILENAME))
            .expect("proxy secret must carry an authorized_principals file");

        // The file must name exactly this attempt's run ID and nothing else — in particular not "root",
        // which would make every run's client cert authenticate to every proxy (R3 / T-INFO-3).
        assert_eq!(principals.trim(), "run-1");
        assert!(
            !principals.contains("root"),
            "authorized_principals must not contain 'root', or cross-run isolation is void"
        );
    }

    #[test]
    fn sshd_config_forces_the_enter_host_script_and_has_no_pam_directive() {
        let config = render_sshd_config();
        assert!(config.contains(&format!(
            "ForceCommand {SSHD_CONFIG_MOUNT_PATH}/{ENTER_HOST_SCRIPT_FILENAME}"
        )));
        assert!(config.contains("TrustedUserCAKeys"));
        // Per-run principal enforcement: without this line sshd falls back to accepting any cert
        // whose principals include the login user, defeating cross-run isolation (R3 / T-INFO-3).
        assert!(config.contains(&format!(
            "AuthorizedPrincipalsFile {SSHD_CONFIG_MOUNT_PATH}/{AUTHORIZED_PRINCIPALS_FILENAME}"
        )));
        // Required so sshd will actually READ the AuthorizedPrincipalsFile off the Kubernetes Secret
        // mount — under the default `StrictModes yes`, secure_filename refuses the tmpfs/symlinked
        // path and sshd discards the file, denying every login with `Permission denied (publickey)`.
        assert!(config.contains("StrictModes no"));
        // HostCertificate isn't auto-discovered from the HostKey filename — omitting it makes
        // sshd present a bare key, failing host-key verification for `@cert-authority` clients.
        assert!(config.contains(&format!(
            "HostCertificate {SSHD_CONFIG_MOUNT_PATH}/{HOST_CERT_FILENAME}"
        )));
        assert!(!config.contains("ChrootDirectory"));
        assert!(!config.contains("UsePAM"));
        // Without this line sshd rejects the sftp subsystem before ForceCommand ever runs.
        assert!(config.contains(&format!("Subsystem sftp {SFTP_SUBSYSTEM_MARKER}")));
    }

    #[test]
    fn enter_host_script_nsenters_via_host_proc_and_handles_both_command_forms() {
        let script = render_enter_host_script();
        assert!(script.contains(&format!("{HOST_PROC_MOUNT_PATH}/1/ns")));
        // Glued short-option form, not `--mount=`/etc — BusyBox's nsenter doesn't parse the long form.
        assert!(script.contains("-m\"$NS/mnt\""));
        assert!(script.contains("-n\"$NS/net\""));
        assert!(script.contains("-i\"$NS/ipc\""));
        assert!(script.contains("-u\"$NS/uts\""));
        // No `-p`/pid join — hostPID: true on the PodSpec covers this instead.
        assert!(!script.contains("-p\""));
        assert!(script.contains("SSH_ORIGINAL_COMMAND"));
    }

    #[test]
    fn enter_host_script_recognizes_sftp_marker_and_searches_common_server_paths() {
        let script = render_enter_host_script();
        assert!(script.contains(&format!(
            "\"$SSH_ORIGINAL_COMMAND\" = \"{SFTP_SUBSYSTEM_MARKER}\""
        )));
        for candidate in [
            "/usr/lib/openssh/sftp-server",
            "/usr/libexec/openssh/sftp-server",
            "/usr/lib/ssh/sftp-server",
            "/usr/lib/misc/sftp-server",
            "/usr/lib64/misc/sftp-server",
            "/usr/lib64/openssh/sftp-server",
        ] {
            assert!(
                script.contains(candidate),
                "missing candidate path {candidate}"
            );
        }
    }

    fn toleration(key: &str) -> Toleration {
        Toleration {
            key: Some(key.to_string()),
            operator: Some("Exists".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn default_tolerations_cover_notready_taints_in_every_effect() {
        let merged = merge_default_tolerations(None);

        for key in [NODE_NOT_READY_TAINT, NODE_UNREACHABLE_TAINT] {
            let t = merged
                .iter()
                .find(|t| t.key.as_deref() == Some(key))
                .unwrap_or_else(|| panic!("missing default toleration for {key}"));
            assert_eq!(t.operator.as_deref(), Some("Exists"));
            // Empty effect is load-bearing: it matches BOTH NoSchedule (needed to *schedule onto* an
            // already-NotReady node) and NoExecute — not just NoExecute like a DaemonSet.
            assert_eq!(t.effect, None, "{key} toleration must not pin an effect");
            assert_eq!(
                t.toleration_seconds, None,
                "{key} must tolerate indefinitely"
            );
        }
    }

    #[test]
    fn user_tolerations_are_merged_and_not_duplicated() {
        let user = vec![
            toleration("node-role.kubernetes.io/control-plane"),
            // A user-supplied not-ready toleration must win — no duplicate default for it.
            toleration(NODE_NOT_READY_TAINT),
        ];
        let merged = merge_default_tolerations(Some(&user));

        assert_eq!(
            merged
                .iter()
                .filter(|t| t.key.as_deref() == Some(NODE_NOT_READY_TAINT))
                .count(),
            1,
            "the user's not-ready toleration must not be duplicated"
        );
        assert!(
            merged
                .iter()
                .any(|t| t.key.as_deref() == Some("node-role.kubernetes.io/control-plane")),
            "user tolerations must be preserved"
        );
        assert!(
            merged
                .iter()
                .any(|t| t.key.as_deref() == Some(NODE_UNREACHABLE_TAINT)),
            "the unreachable default must still be added"
        );
    }

    fn pod_with(
        phase: Option<&str>,
        ready: bool,
        pod_ip: Option<&str>,
        created_secs: Option<i64>,
    ) -> Pod {
        use k8s_openapi::api::core::v1::{PodCondition, PodStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        use k8s_openapi::jiff::Timestamp;

        Pod {
            metadata: ObjectMeta {
                creation_timestamp: created_secs.map(|s| Time(Timestamp::from_second(s).unwrap())),
                ..Default::default()
            },
            status: Some(PodStatus {
                phase: phase.map(|p| p.to_string()),
                pod_ip: pod_ip.map(|s| s.to_string()),
                conditions: Some(vec![PodCondition {
                    type_: "Ready".to_string(),
                    status: if ready { "True" } else { "False" }.to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn proxy_pod_readiness_classifies_by_ready_ip_and_phase() {
        assert_eq!(
            proxy_pod_readiness(&pod_with(Some("Running"), true, Some("10.0.0.5"), Some(0))),
            PodReadyState::ReadyWithIp("10.0.0.5".to_string())
        );
        // Ready condition true but no IP yet ⇒ not usable; falls through to phase (Running ⇒ wait).
        assert_eq!(
            proxy_pod_readiness(&pod_with(Some("Running"), true, None, Some(0))),
            PodReadyState::Running
        );
        assert_eq!(
            proxy_pod_readiness(&pod_with(Some("Running"), false, None, Some(0))),
            PodReadyState::Running
        );
        assert_eq!(
            proxy_pod_readiness(&pod_with(Some("Pending"), false, None, Some(0))),
            PodReadyState::PreRunning
        );
        assert_eq!(
            proxy_pod_readiness(&pod_with(Some("Unknown"), false, None, Some(0))),
            PodReadyState::PreRunning
        );
        assert_eq!(
            proxy_pod_readiness(&pod_with(None, false, None, Some(0))),
            PodReadyState::PreRunning
        );
    }

    /// A pod deleted by `reset_incomplete_run` keeps `Running`/`Ready=True`/a pod IP for its whole
    /// termination grace period. Adopting it would hand the run a proxy still serving the previous
    /// CA's host certificate — and, because it looks Ready, would let the Job launch against it.
    #[test]
    fn a_terminating_proxy_pod_is_never_adopted_even_while_it_still_looks_ready() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        use k8s_openapi::jiff::Timestamp;

        let mut pod = pod_with(Some("Running"), true, Some("10.0.0.5"), Some(0));
        pod.metadata.deletion_timestamp = Some(Time(Timestamp::from_second(0).unwrap()));

        assert_eq!(proxy_pod_readiness(&pod), PodReadyState::Terminating);
    }

    #[test]
    fn terminating_pod_wait_age_starts_at_deletion_not_creation() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        use k8s_openapi::jiff::Timestamp;

        let mut pod = pod_with(Some("Running"), true, Some("10.0.0.5"), Some(100));
        pod.metadata.deletion_timestamp = Some(Time(Timestamp::from_second(900).unwrap()));

        assert_eq!(
            proxy_wait_age_secs(&pod, &PodReadyState::Terminating, 1_000),
            Some(100)
        );
        assert_eq!(
            proxy_wait_age_secs(&pod, &PodReadyState::PreRunning, 1_000),
            Some(900)
        );
        assert_eq!(
            proxy_wait_age_secs(&pod, &PodReadyState::Running, 1_000),
            None
        );
    }

    fn node_with_ready_heartbeat(heartbeat_secs: Option<i64>) -> Node {
        use k8s_openapi::api::core::v1::{NodeCondition, NodeStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        use k8s_openapi::jiff::Timestamp;

        Node {
            status: Some(NodeStatus {
                conditions: Some(vec![NodeCondition {
                    type_: "Ready".to_string(),
                    status: "Unknown".to_string(),
                    last_heartbeat_time: heartbeat_secs
                        .map(|s| Time(Timestamp::from_second(s).unwrap())),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn node_heartbeat_age_is_now_minus_last_heartbeat_or_none() {
        let node = node_with_ready_heartbeat(Some(1_000));
        assert_eq!(node_ready_heartbeat_age_secs(&node, 1_300), Some(300));

        // No timestamp on the Ready condition ⇒ None.
        assert_eq!(
            node_ready_heartbeat_age_secs(&node_with_ready_heartbeat(None), 1_300),
            None
        );
        // No status/conditions ⇒ None.
        assert_eq!(node_ready_heartbeat_age_secs(&Node::default(), 1_300), None);
    }

    fn policy(aggressiveness: u32) -> ProxyGracePolicy {
        ProxyGracePolicy::new(600, aggressiveness, [3, 7, 30])
    }

    const DAY: i64 = 86_400;

    #[test]
    fn effective_grace_halves_per_tier_by_default_then_drops_to_zero() {
        let p = policy(2);
        assert_eq!(effective_grace_secs(Some(2 * DAY), &p), 600); // <=3d  → full
        assert_eq!(effective_grace_secs(Some(5 * DAY), &p), 300); // <=7d  → /2
        assert_eq!(effective_grace_secs(Some(20 * DAY), &p), 150); // <=30d → /4
        assert_eq!(effective_grace_secs(Some(40 * DAY), &p), 0); // older → 0
        // Boundary equality lands in the lower (earlier) tier.
        assert_eq!(effective_grace_secs(Some(3 * DAY), &p), 600);
        assert_eq!(effective_grace_secs(Some(7 * DAY), &p), 300);
        // Unknown heartbeat ⇒ conservative full grace.
        assert_eq!(effective_grace_secs(None, &p), 600);
    }

    #[test]
    fn effective_grace_respects_aggressiveness_and_clamps_zero() {
        let p = policy(4);
        assert_eq!(effective_grace_secs(Some(2 * DAY), &p), 600);
        assert_eq!(effective_grace_secs(Some(5 * DAY), &p), 150); // /4
        assert_eq!(effective_grace_secs(Some(20 * DAY), &p), 37); // /16 (integer)

        // aggressiveness 0 is clamped to 1 in `new` — no divide-by-zero, no reduction.
        let flat = policy(0);
        assert_eq!(flat.aggressiveness, 1);
        assert_eq!(effective_grace_secs(Some(5 * DAY), &flat), 600);
        assert_eq!(effective_grace_secs(Some(20 * DAY), &flat), 600);
        assert_eq!(effective_grace_secs(Some(40 * DAY), &flat), 0);
    }
}

/// Container-backed integration test for the R3 cross-run isolation property: a *real* sshd (the
/// production proxy image) configured entirely by `build_secret`/`render_sshd_config` must accept
/// this run's client cert and reject another run's — purely on sshd's `AuthorizedPrincipalsFile`
/// principal check, with the per-run NetworkPolicy out of the picture. It also exercises the host
/// cert / `@cert-authority` known_hosts path.
///
/// NOTE: this test injects config via copy-to-container (a normal root-owned image-layer directory),
/// so it does *not* reproduce the Kubernetes Secret tmpfs mount whose permissions make sshd's
/// `secure_filename` refuse the `AuthorizedPrincipalsFile` under the default `StrictModes yes` — the
/// real-cluster failure that forced `StrictModes no` in `render_sshd_config`. It therefore validates
/// the principal *logic*, not the on-cluster mount permissions; keep the `StrictModes no` unit
/// assertion as the guard for the latter.
///
/// `#[ignore]`d by default — it needs a Docker/Podman API socket and an OpenSSH `ssh` client on the
/// runner. With rootless podman (`systemctl --user start podman.socket`), run:
///   ```text
///   export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock" \
///   export TESTCONTAINERS_RYUK_DISABLED=true \
///   cargo test managed_ssh::container_tests -- --ignored --nocapture
///   ```
/// (Ryuk — testcontainers' reaper sidecar — is flaky under rootless podman; disabling it is safe
/// here because `ContainerAsync`'s `Drop` removes the proxy container at test end.)
///
/// SELinux / rootless-podman note: the sshd config files are injected with testcontainers'
/// copy-to-container, so they land in the container's own image layer — owned by container-root and
/// labeled `container_file_t` automatically. A host bind mount would instead need `:Z` relabeling on
/// an SELinux-enforcing host *and* would carry the host uid, which sshd's StrictModes rejects as bad
/// ownership on `AuthorizedPrincipalsFile`/the host key. Copy-to sidesteps both, matching prod's
/// root-owned read-only Secret mount.
#[cfg(test)]
mod container_tests {
    use super::*;
    use crate::v1beta1::ca::CertificateAuthority;
    use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use testcontainers::core::{IntoContainerPort, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{GenericImage, ImageExt};

    /// Proxy image this test boots: the **first-party** minimal static sshd from `Containerfile.sshd`,
    /// so this test is that image's conformance gate. A local `--ignored` run needs it built first:
    ///   podman build -f Containerfile.sshd -t ghcr.io/webd97/ansible-operator-sshd:10.4p1-1 .
    ///   cargo test managed_ssh::container_tests -- --ignored --nocapture
    /// Override `MANAGED_SSH_TEST_IMAGE`/`MANAGED_SSH_TEST_TAG` to test a candidate build (e.g. an
    /// OpenSSH-bump PR) — a local-only image is used as-is (testcontainers only pulls on a 404).
    fn proxy_image() -> String {
        std::env::var("MANAGED_SSH_TEST_IMAGE")
            .unwrap_or_else(|_| "ghcr.io/webd97/ansible-operator-sshd".to_string())
    }
    fn proxy_tag() -> String {
        std::env::var("MANAGED_SSH_TEST_TAG").unwrap_or_else(|_| "10.4p1-1".to_string())
    }
    /// Node name the proxy's host cert is signed for; the client must dial it via `HostKeyAlias`
    /// (mirroring `inventory_renderer`) so the `@cert-authority *` known_hosts entry validates.
    const HOST_NAME: &str = "worker-1";

    /// Writes a rendered client-cert file map to `dir`, tightening the private key to 0600 so the
    /// `ssh` client doesn't refuse it as too open.
    fn write_client_files(dir: &Path, files: &BTreeMap<String, String>) {
        for (name, contents) in files {
            let path = dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .write_all(contents.as_bytes())
                .unwrap();
            let mode = if name == paths::MANAGED_SSH_CLIENT_KEY_FILENAME {
                0o600
            } else {
                0o644
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    /// Runs the real `ssh` client against the proxy on `port`, presenting `client_dir`'s cert and
    /// mirroring production's connection options (`UserKnownHostsFile` + `HostKeyAlias`,
    /// publickey-only, batch mode).
    fn ssh_attempt(port: u16, client_dir: &Path) -> std::process::Output {
        let opt = |k: &str, v: String| format!("{k}={v}");
        std::process::Command::new("ssh")
            .args(["-F", "/dev/null"])
            .arg("-i")
            .arg(client_dir.join(paths::MANAGED_SSH_CLIENT_KEY_FILENAME))
            .arg("-o")
            .arg(opt(
                "CertificateFile",
                client_dir
                    .join(paths::MANAGED_SSH_CLIENT_CERT_FILENAME)
                    .display()
                    .to_string(),
            ))
            .arg("-o")
            .arg(opt(
                "UserKnownHostsFile",
                client_dir
                    .join(paths::MANAGED_SSH_KNOWN_HOSTS_FILENAME)
                    .display()
                    .to_string(),
            ))
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .arg("-o")
            .arg(opt("HostKeyAlias", HOST_NAME.to_string()))
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "PreferredAuthentications=publickey"])
            .args(["-o", "ConnectTimeout=10"])
            .args(["-p", &port.to_string()])
            .arg("root@127.0.0.1")
            .arg("true")
            .output()
            .expect("failed to spawn `ssh`; is an OpenSSH client installed on the runner?")
    }

    #[tokio::test]
    #[ignore = "requires a Docker/Podman API socket and an ssh client"]
    async fn proxy_rejects_other_runs_cert_and_accepts_its_own() {
        let ca = CertificateAuthority::generate().unwrap();
        let run_b = calculate_execution_hash("plan-b", std::iter::empty());

        // Server: proxy config for run B — host cert principal = HOST_NAME, and the
        // AuthorizedPrincipalsFile carries only run B's run ID.
        let server_files = build_secret("proxy-b", &run_b, "run-b", HOST_NAME, &ca)
            .unwrap()
            .string_data
            .expect("proxy secret must carry string_data");

        // Clients: run B's cert (must be accepted) and run A's cert (must be rejected), both off
        // the same CA — so only the principal, not the signature, distinguishes them.
        let client_b = tempfile::tempdir().unwrap();
        let client_a = tempfile::tempdir().unwrap();
        write_client_files(
            client_b.path(),
            &render_client_cert_files(&ca, "run-b").unwrap(),
        );
        write_client_files(
            client_a.path(),
            &render_client_cert_files(&ca, "run-a").unwrap(),
        );

        // Boot the real proxy image with our rendered config injected into its own fs layer. The
        // chmod reproduces the Secret's 0500 default_mode; then exec sshd with the exact prod flags.
        let start_cmd = format!(
            "chmod 0500 {SSHD_CONFIG_MOUNT_PATH}/* && exec /usr/sbin/sshd -D -e -f {SSHD_CONFIG_MOUNT_PATH}/sshd_config"
        );
        let mut request = GenericImage::new(proxy_image(), proxy_tag())
            .with_exposed_port((PROXY_SSH_PORT as u16).tcp())
            .with_wait_for(WaitFor::message_on_stderr("Server listening"))
            .with_cmd(vec!["sh".to_string(), "-c".to_string(), start_cmd]);
        for (name, contents) in &server_files {
            request = request.with_copy_to(
                format!("{SSHD_CONFIG_MOUNT_PATH}/{name}"),
                contents.clone().into_bytes(),
            );
        }
        let container = request
            .start()
            .await
            .expect("proxy sshd container failed to start (check sshd_config / StrictModes)");
        let port = container
            .get_host_port_ipv4((PROXY_SSH_PORT as u16).tcp())
            .await
            .unwrap();

        // Same-run cert: must pass host-cert verification AND user auth, reaching the ForceCommand.
        // The forced `enter-host.sh` then nsenters into /host/proc/1/ns/* which doesn't exist here
        // (and rootless lacks CAP_SYS_ADMIN), so it errors via `nsenter` — that's the success signal
        // that we got *past* authentication.
        let accepted = ssh_attempt(port, client_b.path());
        let accepted_err = String::from_utf8_lossy(&accepted.stderr);
        assert!(
            !accepted_err.contains("Permission denied"),
            "run B's own cert was rejected by its proxy:\n{accepted_err}"
        );
        assert!(
            accepted_err.contains("nsenter"),
            "run B's cert did not reach the ForceCommand — host-cert or auth failed:\n{accepted_err}"
        );

        // Foreign cert (run A's run ID): sshd must refuse it at the AuthorizedPrincipalsFile check.
        let rejected = ssh_attempt(port, client_a.path());
        let rejected_err = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            rejected_err.contains("Permission denied"),
            "run A's cert was NOT rejected by run B's proxy — cross-run isolation is broken:\n{rejected_err}"
        );
    }
}
