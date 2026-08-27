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

    if let Some(requirements) = &object.spec.template.requirements {
        string_data.insert("requirements.yml".into(), requirements.to_owned());
    }

    for (index, variable_set) in inlined_variables.into_iter().enumerate() {
        string_data.insert(format!("static-variables-{index}.yml"), variable_set?);
    }

    secret.string_data = Some(string_data);

    Ok(secret)
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
