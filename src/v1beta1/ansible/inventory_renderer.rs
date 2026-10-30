use std::collections::BTreeMap;

use serde::{Serialize, Serializer};

use crate::v1beta1::ResolvedInventoryGroup;

/// Host variables this module renders itself to drive connection and isolation. Inventory authors
/// may not set these as group `variables` — the operator owns them, and (for the host-level ones)
/// Ansible's host-var precedence would silently override an author's group var anyway. Rejecting
/// them at resolve time turns a silently-ignored setting into a clear error. The
/// `reserved_vars_cover_every_rendered_host_var` test keeps this list in step with what is actually
/// emitted below.
pub const RESERVED_HOST_VARS: &[&str] = &[
    "ansible_host",
    "ansible_port",
    "ansible_user",
    "ansible_ssh_private_key_file",
    "ansible_ssh_common_args",
];

/// The account every managed-ssh connection logs in as: the only one the proxy's sshd has
/// (`PermitRootLogin yes`), and the login principal of the run's client cert. Rendered explicitly
/// because ssh otherwise logs in as the local user, which is not root in a non-root image.
pub const MANAGED_SSH_USER: &str = "root";

/// SSH options that give up on a host that stopped answering, after about two minutes. A host that
/// dies or drops off the network mid-task sends nothing to close the connection, and with no
/// traffic only TCP keepalive would notice, after more than two hours. Ansible waits for every host
/// of a task, so until then the whole run, and every host Lease it holds, waits with it. Not
/// shorter: a managed-ssh connection runs over the pod network, so a task that restarts the target
/// Node's container runtime or network plugin interrupts its own connection for a while.
const DEAD_HOST_SSH_ARGS: &str = "-o ServerAliveInterval=15 -o ServerAliveCountMax=8";

/// Returns the first [`RESERVED_HOST_VARS`] key present in an author's group `variables`, if any.
/// `variables` is the raw JSON object the author supplied; a non-object value has no top-level keys
/// and so never conflicts here (the CRD schema already constrains it to an object).
pub fn first_reserved_var(variables: &serde_json::Value) -> Option<&'static str> {
    let object = variables.as_object()?;
    RESERVED_HOST_VARS
        .iter()
        .copied()
        .find(|key| object.contains_key(*key))
}

/// How a managed-ssh host in this run can be reached, if it can — proxy pod IPs are only known once
/// the pods are Ready, so this is threaded in by the caller.
///
/// `Unreachable` carries no address on purpose. Such a host is still rendered into its groups, so
/// `groups[]` keeps describing the full fleet, but it gets no connection vars and the run excludes
/// it with `--limit`, so nothing ever dials it.
pub enum ManagedSshHostInfo {
    Proxy { pod_ip: String, port: i32 },
    Unreachable,
}

pub struct RenderContext<'a> {
    pub managed_ssh_hosts: &'a BTreeMap<String, ManagedSshHostInfo>,
    pub managed_ssh_client_key_path: &'a str,
    pub managed_ssh_known_hosts_path: &'a str,
    /// `StaticInventory` resource name -> (private key mount path, known_hosts mount path).
    /// Resolved by the caller (which owns the mount-path conventions in
    /// `controllers::playbookplancontroller::paths`) rather than computed here, so this module
    /// stays decoupled from controller-internal path conventions.
    pub ssh_paths_by_static_inventory: &'a BTreeMap<String, (String, String)>,
}

pub fn render_inventory(
    groups: &[ResolvedInventoryGroup],
    ctx: &RenderContext,
) -> Result<String, super::RenderError> {
    let inventory = groups
        .iter()
        .map(|group| {
            let hosts = group.hosts();
            let host_entries = hosts
                .hosts
                .iter()
                .map(|hostname| {
                    let vars = match group {
                        ResolvedInventoryGroup::ManagedSsh { .. } => {
                            render_managed_ssh_host_vars(hostname, ctx)
                        }
                        ResolvedInventoryGroup::Ssh {
                            static_inventory_name,
                            config,
                            ..
                        } => render_ssh_host_vars(static_inventory_name, config, ctx),
                    };
                    (hostname.as_str(), vars)
                })
                .collect();

            // Author-supplied group variables become Ansible group `vars:`. They rank below the
            // per-host connection vars above in Ansible precedence, so they can never override the
            // managed-ssh/SSH wiring the operator renders — reserved keys are rejected at resolve
            // time regardless (see `first_reserved_var`).
            let vars = group
                .variables()
                .and_then(|variables| variables.0.as_object())
                .filter(|vars| !vars.is_empty());

            (
                hosts.name.as_str(),
                InventoryGroup {
                    hosts: OrderedMap(host_entries),
                    vars,
                },
            )
        })
        .collect();

    Ok(super::yaml_node::to_string(&OrderedMap(inventory))?)
}

#[derive(Serialize)]
struct InventoryGroup<'a> {
    hosts: OrderedMap<'a, HostVars>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vars: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize, Default)]
struct HostVars {
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_ssh_private_key_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_ssh_common_args: Option<String>,
}

/// A mapping that keeps its entries in the order given: Ansible lists hosts in inventory order,
/// and that order decides which hosts share a `serial` batch.
struct OrderedMap<'a, V>(Vec<(&'a str, V)>);

impl<V: Serialize> Serialize for OrderedMap<'_, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(key, value)| (key, value)))
    }
}

fn render_managed_ssh_host_vars(hostname: &str, ctx: &RenderContext) -> HostVars {
    let (ansible_host, ansible_port) = match ctx.managed_ssh_hosts.get(hostname) {
        Some(ManagedSshHostInfo::Proxy { pod_ip, port }) => (Some(pod_ip.clone()), Some(*port)),
        _ => (None, None),
    };

    HostVars {
        ansible_host,
        ansible_port,
        ansible_user: Some(MANAGED_SSH_USER.into()),
        ansible_ssh_private_key_file: Some(ctx.managed_ssh_client_key_path.to_string()),
        // ansible_host is the proxy pod's IP, but the host cert's principal (and the wildcard
        // @cert-authority known_hosts line) is the node's name — without HostKeyAlias, the SSH
        // client checks the cert/known_hosts entry against the dialed IP, not the node name, and
        // rejects with "Certificate invalid: name is not a listed principal" even though
        // everything else is correctly signed.
        ansible_ssh_common_args: Some(format!(
            "-o UserKnownHostsFile={} -o HostKeyAlias={hostname} {DEAD_HOST_SSH_ARGS}",
            ctx.managed_ssh_known_hosts_path
        )),
    }
}

fn render_ssh_host_vars(
    static_inventory_name: &str,
    config: &crate::v1beta1::SshConfig,
    ctx: &RenderContext,
) -> HostVars {
    let mut vars = HostVars {
        ansible_user: Some(config.user.clone()),
        ..Default::default()
    };

    if let Some((key_path, known_hosts_path)) =
        ctx.ssh_paths_by_static_inventory.get(static_inventory_name)
    {
        vars.ansible_ssh_private_key_file = Some(key_path.clone());
        vars.ansible_ssh_common_args = Some(format!(
            "-o UserKnownHostsFile={known_hosts_path} {DEAD_HOST_SSH_ARGS}"
        ));
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::{GenericMap, ResolvedHosts, SecretRef, SshConfig};

    #[test]
    fn renders_managed_ssh_group_with_proxy_ip_and_cert_paths() {
        let group = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        };

        let mut managed_ssh_hosts = BTreeMap::new();
        managed_ssh_hosts.insert(
            "worker-1".to_string(),
            ManagedSshHostInfo::Proxy {
                pod_ip: "10.0.0.5".into(),
                port: 22,
            },
        );

        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[group], &ctx).unwrap();

        assert!(rendered.contains("ansible_host: \"10.0.0.5\""));
        assert!(rendered.contains("ansible_port: 22"));
        // Explicit, so a non-root image does not log in as its own user, which the proxy lacks.
        assert!(rendered.contains("ansible_user: root"));
        assert!(rendered.contains("client_key"));
        // The host cert's principal is the node name, not the proxy pod IP dialed via
        // ansible_host, so the SSH client needs HostKeyAlias to check the cert/known_hosts
        // entry against the right name.
        assert!(rendered.contains("-o HostKeyAlias=worker-1"));
        assert!(rendered.contains(DEAD_HOST_SSH_ARGS));
    }

    /// An unreachable host stays a full member of its group — that membership is what a playbook
    /// templating a fleet list out of `groups[]` reads — but gets no address, because the run
    /// excludes it with `--limit` rather than dialling it. Rendering one would be a second, weaker
    /// answer to a question the operator has already settled.
    #[test]
    fn renders_unreachable_host_into_its_group_without_an_address() {
        let group = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into(), "worker-9".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        };

        let mut managed_ssh_hosts = BTreeMap::new();
        managed_ssh_hosts.insert(
            "worker-1".to_string(),
            ManagedSshHostInfo::Proxy {
                pod_ip: "10.0.0.5".into(),
                port: 22,
            },
        );
        managed_ssh_hosts.insert("worker-9".to_string(), ManagedSshHostInfo::Unreachable);

        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[group], &ctx).unwrap();

        assert!(rendered.contains("worker-9:"));
        assert!(rendered.contains("-o HostKeyAlias=worker-9"));
        // The only address in the rendering belongs to the host that has one.
        assert_eq!(rendered.matches("ansible_host").count(), 1);
        assert!(rendered.contains("ansible_host: \"10.0.0.5\""));
    }

    #[test]
    fn renders_ssh_group_from_static_inventorys_own_config() {
        let group = ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: "external-devices".into(),
                hosts: vec!["ccu.fritz.box".into()],
                ..Default::default()
            },
            static_inventory_name: "ccu".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef {
                    name: "ssh-key".into(),
                },
            },
            variables: None,
        };

        let managed_ssh_hosts = BTreeMap::new();
        let mut ssh_paths = BTreeMap::new();
        ssh_paths.insert(
            "ccu".to_string(),
            (
                "/run/ansible-operator/ssh/ccu/id_rsa".to_string(),
                "/run/ansible-operator/ssh/ccu/known_hosts".to_string(),
            ),
        );
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "unused",
            managed_ssh_known_hosts_path: "unused",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[group], &ctx).unwrap();

        assert!(rendered.contains("ansible_user: root"));
        assert!(rendered.contains("/run/ansible-operator/ssh/ccu/id_rsa"));
        assert!(rendered.contains(DEAD_HOST_SSH_ARGS));
    }

    #[test]
    fn mixed_run_renders_both_groups_without_cross_contamination() {
        let managed = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        };
        let ssh = ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: "external-devices".into(),
                hosts: vec!["ccu.fritz.box".into()],
                ..Default::default()
            },
            static_inventory_name: "ccu".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef {
                    name: "ssh-key".into(),
                },
            },
            variables: None,
        };

        let managed_ssh_hosts = BTreeMap::new();
        let mut ssh_paths = BTreeMap::new();
        ssh_paths.insert(
            "ccu".to_string(),
            (
                "/run/ansible-operator/ssh/ccu/id_rsa".to_string(),
                "/run/ansible-operator/ssh/ccu/known_hosts".to_string(),
            ),
        );
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[managed, ssh], &ctx).unwrap();

        assert!(rendered.contains("controlplanes"));
        assert!(rendered.contains("external-devices"));
        assert!(rendered.contains("ansible_user: root"));
        assert!(rendered.contains("/run/ansible-operator/ssh/ccu/id_rsa"));
    }

    #[test]
    fn renders_author_group_variables_as_group_vars() {
        let group = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: Some(GenericMap(serde_json::json!({
                "ansible_python_interpreter": "/usr/bin/python3.11",
            }))),
        };

        let mut managed_ssh_hosts = BTreeMap::new();
        managed_ssh_hosts.insert(
            "worker-1".to_string(),
            ManagedSshHostInfo::Proxy {
                pod_ip: "10.0.0.5".into(),
                port: 22,
            },
        );
        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[group], &ctx).unwrap();

        // The author's variable lands under the group's `vars:`, not under a host.
        assert!(rendered.contains("vars:"));
        assert!(rendered.contains("ansible_python_interpreter: /usr/bin/python3.11"));
    }

    /// Ansible reads the inventory as YAML 1.1, where a plain `yes`, `on`, `no` or `off` is a
    /// boolean. A string the author set has to reach the playbook as that string — a template
    /// writing `permit_root_login` into `sshd_config` must not see `False`.
    #[test]
    fn string_variables_stay_strings_for_a_yaml_1_1_reader() {
        let group = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: Some(GenericMap(serde_json::json!({
                "a_yes": "yes",
                "b_on": "on",
                "c_no": "no",
                "d_off": "off",
                "e_bool": true,
            }))),
        };

        let managed_ssh_hosts = BTreeMap::new();
        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[group], &ctx).unwrap();

        assert!(
            rendered.contains(
                "a_yes: \"yes\"\n    b_on: \"on\"\n    c_no: \"no\"\n    d_off: \"off\"\n    e_bool: true\n"
            ),
            "{rendered}"
        );
    }

    /// Ansible lists a group's hosts in inventory order, which decides the `serial` batches, so
    /// groups and hosts render in the order they were resolved rather than sorted.
    #[test]
    fn groups_and_hosts_keep_their_resolved_order() {
        let group = |name: &str, hosts: &[&str]| ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: name.into(),
                hosts: hosts.iter().map(|host| host.to_string()).collect(),
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        };

        let managed_ssh_hosts = BTreeMap::new();
        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(
            &[
                group("workers", &["worker-2", "worker-1"]),
                group("controlplanes", &["cp-1"]),
            ],
            &ctx,
        )
        .unwrap();

        let positions: Vec<usize> = ["workers:", "worker-2:", "worker-1:", "controlplanes:"]
            .iter()
            .map(|needle| rendered.find(needle).expect(needle))
            .collect();
        assert!(positions.is_sorted(), "{rendered}");
    }

    /// The other half of the rule `execution_evaluator::renders_group_vars` mirrors: an empty
    /// `variables` map renders exactly what an absent one does. The hash skips such a group on the
    /// strength of that, so if this ever started emitting an empty `vars:` block the two would
    /// disagree — and the group's real, rendered content would stop being what the hash covers.
    #[test]
    fn an_empty_variables_map_renders_the_same_as_no_variables_at_all() {
        let group = |variables| ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-1".into()],
                ..Default::default()
            },
            tolerations: None,
            variables,
        };

        let mut managed_ssh_hosts = BTreeMap::new();
        managed_ssh_hosts.insert(
            "worker-1".to_string(),
            ManagedSshHostInfo::Proxy {
                pod_ip: "10.0.0.5".into(),
                port: 22,
            },
        );
        let ssh_paths = BTreeMap::new();
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let empty = render_inventory(&[group(Some(GenericMap(serde_json::json!({}))))], &ctx)
            .expect("an empty variables map is renderable");
        let absent = render_inventory(&[group(None)], &ctx).expect("no variables is renderable");

        assert_eq!(empty, absent, "byte-identical, so the hash must not move");
        assert!(!empty.contains("vars:"));
    }

    #[test]
    fn reserved_vars_cover_every_rendered_host_var() {
        // Render one host of each connection kind, then assert every `ansible_*` var the operator
        // itself writes is declared reserved. This keeps RESERVED_HOST_VARS from drifting behind
        // the renderer, so an author can never quietly shadow a connection var the operator
        // manages.
        let managed = ResolvedInventoryGroup::ManagedSsh {
            hosts: ResolvedHosts {
                name: "controlplanes".into(),
                hosts: vec!["worker-9".into()],
                ..Default::default()
            },
            tolerations: None,
            variables: None,
        };
        let ssh = ResolvedInventoryGroup::Ssh {
            hosts: ResolvedHosts {
                name: "external-devices".into(),
                hosts: vec!["ccu.fritz.box".into()],
                ..Default::default()
            },
            static_inventory_name: "ccu".into(),
            config: SshConfig {
                user: "root".into(),
                secret_ref: SecretRef {
                    name: "ssh-key".into(),
                },
            },
            variables: None,
        };

        let mut managed_ssh_hosts = BTreeMap::new();
        managed_ssh_hosts.insert(
            "worker-9".to_string(),
            ManagedSshHostInfo::Proxy {
                pod_ip: "10.0.0.5".into(),
                port: 22,
            },
        );
        let mut ssh_paths = BTreeMap::new();
        ssh_paths.insert(
            "ccu".to_string(),
            ("/keys/id_rsa".to_string(), "/keys/known_hosts".to_string()),
        );
        let ctx = RenderContext {
            managed_ssh_hosts: &managed_ssh_hosts,
            managed_ssh_client_key_path: "/run/ansible-operator/managed-ssh/client_key",
            managed_ssh_known_hosts_path: "/run/ansible-operator/managed-ssh/known_hosts",
            ssh_paths_by_static_inventory: &ssh_paths,
        };

        let rendered = render_inventory(&[managed, ssh], &ctx).unwrap();
        let parsed: serde_json::Value = serde_saphyr::from_str(&rendered).unwrap();

        for (_group, body) in parsed.as_object().expect("inventory is a mapping") {
            let Some(hosts) = body.get("hosts").and_then(|h| h.as_object()) else {
                continue;
            };
            for (_host, host_vars) in hosts {
                let Some(host_vars) = host_vars.as_object() else {
                    continue;
                };
                for key in host_vars.keys() {
                    if key.starts_with("ansible_") {
                        assert!(
                            RESERVED_HOST_VARS.contains(&key.as_str()),
                            "operator emits `{key}` as a host var but it is missing from RESERVED_HOST_VARS"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn first_reserved_var_flags_operator_owned_keys() {
        let allowed = serde_json::json!({ "ansible_python_interpreter": "/usr/bin/python3" });
        assert_eq!(first_reserved_var(&allowed), None);

        let reserved = serde_json::json!({ "custom": 1, "ansible_user": "root" });
        assert_eq!(first_reserved_var(&reserved), Some("ansible_user"));

        // A non-object has no top-level keys, so it never conflicts here.
        assert_eq!(first_reserved_var(&serde_json::json!("scalar")), None);
    }
}
