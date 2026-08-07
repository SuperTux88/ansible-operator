use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

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
use crate::{
    utils,
    v1beta1::{
        ca::CertificateAuthority,
        controllers::{
            playbookplancontroller::execution_evaluator::ExecutionHash,
            reconcile_error::ReconcileError,
        },
        labels,
        resources::Toleration,
    },
};

pub const PROXY_SSH_PORT: i32 = 22;

const SSHD_CONFIG_MOUNT_PATH: &str = "/etc/ansible-operator-sshd";
const HOST_KEY_FILENAME: &str = "ssh_host_ed25519_key";
const HOST_CERT_FILENAME: &str = "ssh_host_ed25519_key-cert.pub";
const CA_PUB_FILENAME: &str = "ca.pub";
const ENTER_HOST_SCRIPT_FILENAME: &str = "enter-host.sh";

/// Per-run principals file for sshd's `AuthorizedPrincipalsFile`. It contains **only this run's
/// execution hash** (see `build_secret`) — never `root`. That scopes the proxy to certs carrying
/// that run's hash principal, so a leaked/strayed client cert from another run is rejected at the
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
    /// At least one proxy pod is still `Running`-not-yet-Ready or within its pre-`Running` grace
    /// window; `waiting` names them so the caller can report them on the plan.
    Pending { waiting: Vec<String> },
}

/// A proxy pod's k8s state as far as the readiness gate cares: Ready (with its pod IP), still
/// `Running` (waited on indefinitely), or stuck before `Running` (subject to the grace window).
#[derive(Debug, PartialEq)]
enum PodReadyState {
    ReadyWithIp(String),
    Running,
    PreRunning,
}

/// Pure classification of a proxy pod. Ready-condition `True` + a pod IP ⇒ `ReadyWithIp`; else a pod
/// that has reached `Running` ⇒ `Running` (sshd still coming up — waited on with no timeout, as
/// before); anything earlier (`Pending`/`Unknown`/absent phase) ⇒ `PreRunning`, the only state the
/// grace window applies to.
fn proxy_pod_readiness(pod: &Pod) -> PodReadyState {
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

/// The effective grace for a pre-`Running` pod: `grace_seconds / aggressiveness^k` for the first tier
/// `k` whose boundary the heartbeat age falls within, `0` past the last boundary. An unknown age ⇒
/// full grace (never shorten on missing data). A healthy node's heartbeat is always recent, so it
/// always lands in tier 0.
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

/// Deterministic, human-readable resource name for a (host, run) pair. The host is used verbatim
/// (not hashed) since managed-ssh only targets `ClusterInventory` hosts, i.e. real Node names,
/// which are already valid Kubernetes object name components. The run uses `utils::generate_id`'s
/// short-id, matching `job_builder::create_job_for_run`'s Job naming.
fn resource_name(host: &str, execution_hash: &ExecutionHash) -> String {
    format!(
        "ansible-sshd-{host}-{}",
        utils::generate_id(**execution_hash)
    )
}

/// Name of this run's client-cert Secret, shared by `job_builder`'s mount and `ensure_client_cert`.
pub fn client_cert_secret_name(execution_hash: &ExecutionHash) -> String {
    format!("managed-ssh-client-{execution_hash}")
}

fn run_labels(execution_hash: &ExecutionHash, host: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            labels::PLAYBOOKPLAN_HASH.to_string(),
            execution_hash.to_string(),
        ),
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
/// `<hash>` principal check still runs (INV-4 / T-INFO-3); only the file-permission gate is skipped,
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
    // ONLY this run's hash — never "root". This is the sole principal sshd's
    // `AuthorizedPrincipalsFile` will accept, so a client cert from any other run (whose hash
    // differs) is rejected even if it can reach this pod. Must match the client cert's hash
    // principal minted in `ensure_client_cert`.
    string_data.insert(
        AUTHORIZED_PRINCIPALS_FILENAME.to_string(),
        format!("{execution_hash}\n"),
    );
    string_data.insert("sshd_config".to_string(), render_sshd_config());
    string_data.insert(
        ENTER_HOST_SCRIPT_FILENAME.to_string(),
        render_enter_host_script(),
    );

    Ok(Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(run_labels(execution_hash, host)),
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
            labels: Some(run_labels(execution_hash, host)),
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
            labels: Some(BTreeMap::from([(
                labels::PLAYBOOKPLAN_HASH.to_string(),
                execution_hash.to_string(),
            )])),
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

/// Renders this run's client-cert files — private key, a cert signed for `["root", <hash>]`, and
/// the `@cert-authority` known_hosts line — as a `filename -> contents` map. Split out from
/// `ensure_client_cert` (which just wraps this in a Secret) so tests can exercise the exact client
/// material the Job pod mounts against a real sshd, rather than re-deriving it.
///
/// The run hash is the *enforced* principal: each proxy pod's `AuthorizedPrincipalsFile` lists only
/// its own run's hash, so this cert authenticates only to this run's proxies. "root" is kept as a
/// harmless second principal (belt-and-suspenders for sshd's default username check on builds/configs
/// where `AuthorizedPrincipalsFile` isn't in force); `PermitRootLogin yes` authorizes the root login.
fn render_client_cert_files(
    ca: &CertificateAuthority,
    execution_hash: &ExecutionHash,
) -> Result<BTreeMap<String, String>, ReconcileError> {
    let client_key = crate::v1beta1::ca::generate_ephemeral_keypair()?;
    let principal = execution_hash.to_string();
    let client_cert = ca.sign_client_cert(client_key.public_key(), &["root", &principal])?;
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
    ca: &CertificateAuthority,
    plan_owner: &OwnerReference,
) -> Result<(), ReconcileError> {
    let name = client_cert_secret_name(execution_hash);

    if secrets_api.get_opt(&name).await?.is_some() {
        return Ok(());
    }

    let string_data = render_client_cert_files(ca, execution_hash)?;

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name),
            labels: Some(BTreeMap::from([(
                labels::PLAYBOOKPLAN_HASH.to_string(),
                execution_hash.to_string(),
            )])),
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
        let netpol_name = format!("managed-ssh-{:x}", {
            let mut hasher = twox_hash::XxHash3_64::new();
            execution_hash.to_string().hash(&mut hasher);
            hasher.finish()
        });
        let netpol = build_network_policy(
            &netpol_name,
            execution_hash,
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

        ensure_client_cert(&job_secrets_api, execution_hash, ca, plan_owner).await?;
    }

    let now = chrono::Utc::now().timestamp();

    let mut ready = Vec::new();
    let mut unreachable = Vec::new();
    let mut waiting = Vec::new();

    for host in hosts {
        let name = resource_name(host, execution_hash);

        if secrets_api.get_opt(&name).await?.is_none() {
            let secret = build_secret(&name, execution_hash, host, ca)?;
            secrets_api.create(&PostParams::default(), &secret).await?;
        }

        // Create the pod for EVERY host, including a NotReady one — we want to attempt scheduling it.
        let pod = match pods_api.get_opt(&name).await? {
            Some(pod) => pod,
            None => {
                let pod = build_pod(&name, &name, execution_hash, host, tolerations, proxy_image);
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
            // Stuck before Running: give it a heartbeat-scaled grace window, then give up. Fetch the
            // Node only here, so healthy runs incur no extra reads once pods are Running.
            PodReadyState::PreRunning => {
                let heartbeat_age = match nodes_api.get_opt(host).await? {
                    Some(node) => node_ready_heartbeat_age_secs(&node, now),
                    None => None,
                };
                let grace = effective_grace_secs(heartbeat_age, grace_policy);
                let pod_age = pod
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| now - t.0.as_second());
                match pod_age {
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
/// — GC-by-label catches everything tagged with the run's hash regardless of how the inventory
/// drifted since the run started. (The CA is in-memory only, not a Secret, so nothing CA-related is
/// in scope here.) The operator-ns resources can't use ownerReferences, since Kubernetes GC ignores
/// references that cross namespaces (they live in the operator namespace, the Job/PlaybookPlan in the
/// plan namespace). Best-effort: delete errors are ignored, the next run's cleanup retries.
///
/// The client-cert Secret is deleted **by name**, not by the hash label: it lives in the plan
/// namespace where the ansible Job and its pod carry that same `PLAYBOOKPLAN_HASH` label, so a
/// label-scoped `delete_collection` there would also sweep them. Its ownerReference on the
/// PlaybookPlan is the backstop if this explicit delete never runs (operator crash / plan deleted
/// mid-run). Deleting it is not the revocation mechanism — that is the deletion of the proxy pods
/// below, after which the cert authenticates to nothing (INV-4 / T-INFO-3).
///
/// Pods use a tighter selector than the operator-ns Secrets/NetworkPolicy: the ansible Job pod
/// carries the same `PLAYBOOKPLAN_HASH` label (the run's NetworkPolicy targets it by that label) but
/// is NOT proxy infra — it must be reaped by its own Job's `ttlSecondsAfterFinished`, never here.
/// That only collides when the operator and the plan share a namespace, but requiring the per-host
/// `PLAYBOOKPLAN_HOST` label (which only proxy pods carry) excludes the ansible pod cleanly.
pub async fn cleanup_proxy_infra(
    client: &kube::Client,
    operator_namespace: &str,
    job_namespace: &str,
    execution_hash: &ExecutionHash,
    playbookplan_name: &str,
) -> Result<(), ReconcileError> {
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), operator_namespace);
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), operator_namespace);
    let netpol_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), operator_namespace);
    let job_secrets_api: Api<Secret> = Api::namespaced(client.clone(), job_namespace);
    let job_netpol_api: Api<NetworkPolicy> = Api::namespaced(client.clone(), job_namespace);

    let dp = DeleteParams::default();
    let hash_selector = format!("{}={execution_hash}", labels::PLAYBOOKPLAN_HASH);

    // Existence of PLAYBOOKPLAN_HOST spares the ansible Job pod (which lacks it) — see the doc.
    let pods_lp =
        ListParams::default().labels(&format!("{hash_selector},{}", labels::PLAYBOOKPLAN_HOST));
    // Bare hash selector: no other operator-managed Secret/NetworkPolicy carries the hash label.
    let rest_lp = ListParams::default().labels(&hash_selector);

    let _ = pods_api.delete_collection(&dp, &pods_lp).await;
    let _ = secrets_api.delete_collection(&dp, &rest_lp).await;
    let _ = netpol_api.delete_collection(&dp, &rest_lp).await;
    let _ = job_netpol_api
        .delete(
            &super::job_builder::job_network_policy_name(playbookplan_name, execution_hash),
            &dp,
        )
        .await;
    // Plan-namespace client-cert Secret: by name, never by label (would catch the Job/pod). See doc.
    let _ = job_secrets_api
        .delete(&client_cert_secret_name(execution_hash), &dp)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_name_is_deterministic_per_host_and_run() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash_a = calculate_execution_hash("playbook-a", std::iter::empty());
        let hash_b = calculate_execution_hash("playbook-b", std::iter::empty());

        let a1 = resource_name("worker-1", &hash_a);
        let a2 = resource_name("worker-1", &hash_a);
        let b = resource_name("worker-1", &hash_b);
        let other_host = resource_name("worker-2", &hash_a);

        assert_eq!(a1, a2);
        assert_ne!(a1, b, "same host, different run must differ");
        assert_ne!(a1, other_host, "different host, same run must differ");
        assert_eq!(
            a1,
            format!("ansible-sshd-worker-1-{}", utils::generate_id(*hash_a))
        );
    }

    #[test]
    fn proxy_network_policy_adds_egress_only_when_configured() {
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let hash = calculate_execution_hash("playbook", std::iter::empty());
        let ingress_only = build_network_policy("proxy", &hash, "plans", None);
        assert_eq!(
            ingress_only.spec.unwrap().policy_types.unwrap(),
            vec!["Ingress"]
        );

        let with_egress = build_network_policy(
            "proxy",
            &hash,
            "plans",
            Some(vec![NetworkPolicyEgressRule::default()]),
        );
        let spec = with_egress.spec.unwrap();
        assert_eq!(spec.policy_types.unwrap(), vec!["Ingress", "Egress"]);
        assert_eq!(spec.egress.unwrap().len(), 1);
    }

    #[test]
    fn build_secret_writes_the_run_hash_as_the_sole_authorized_principal() {
        use crate::v1beta1::ca::CertificateAuthority;
        use crate::v1beta1::controllers::playbookplancontroller::execution_evaluator::calculate_execution_hash;

        let ca = CertificateAuthority::generate().unwrap();
        let hash = calculate_execution_hash("playbook-a", std::iter::empty());

        let secret = build_secret("ansible-sshd-worker-1-abc", &hash, "worker-1", &ca).unwrap();
        let principals = secret
            .string_data
            .as_ref()
            .and_then(|d| d.get(AUTHORIZED_PRINCIPALS_FILENAME))
            .expect("proxy secret must carry an authorized_principals file");

        // The file must name exactly this run's hash and nothing else — in particular not "root",
        // which would make every run's client cert authenticate to every proxy (R3 / T-INFO-3).
        assert_eq!(principals.trim(), hash.to_string());
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
        let run_a = calculate_execution_hash("plan-a", std::iter::empty());

        // Server: proxy config for run B — host cert principal = HOST_NAME, and the
        // AuthorizedPrincipalsFile carries only run B's hash.
        let server_files = build_secret("proxy-b", &run_b, HOST_NAME, &ca)
            .unwrap()
            .string_data
            .expect("proxy secret must carry string_data");

        // Clients: run B's cert (must be accepted) and run A's cert (must be rejected), both off
        // the same CA — so only the principal, not the signature, distinguishes them.
        let client_b = tempfile::tempdir().unwrap();
        let client_a = tempfile::tempdir().unwrap();
        write_client_files(
            client_b.path(),
            &render_client_cert_files(&ca, &run_b).unwrap(),
        );
        write_client_files(
            client_a.path(),
            &render_client_cert_files(&ca, &run_a).unwrap(),
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

        // Foreign cert (run A's hash): sshd must refuse it at the AuthorizedPrincipalsFile check.
        let rejected = ssh_attempt(port, client_a.path());
        let rejected_err = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            rejected_err.contains("Permission denied"),
            "run A's cert was NOT rejected by run B's proxy — cross-run isolation is broken:\n{rejected_err}"
        );
    }
}
