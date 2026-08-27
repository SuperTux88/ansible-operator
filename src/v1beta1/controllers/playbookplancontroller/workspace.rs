use std::collections::BTreeMap;

use k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::OwnerReference};
use kube::runtime::reflector::Lookup;

use crate::v1beta1::{
    PlaybookPlan, ResolvedInventoryGroup, ansible, controllers::reconcile_error::ReconcileError,
    playbookplancontroller::paths,
};

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
    secret.metadata.name = Some(pb_name.into());

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

    #[test]
    fn a_workspace_without_managed_ssh_hosts_carries_no_preflight_gate() {
        let secret = super::render_secret(&plan(), &[], &BTreeMap::new()).unwrap();
        let data = secret.string_data.unwrap();

        assert!(!data.contains_key(paths::MANAGED_SSH_PREFLIGHT_SCRIPT_FILENAME));
        assert!(!data.contains_key(paths::MANAGED_SSH_PREFLIGHT_ENDPOINTS_FILENAME));
    }
}
