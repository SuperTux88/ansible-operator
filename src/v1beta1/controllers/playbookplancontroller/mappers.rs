use std::sync::Arc;

use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector::{ObjectRef, Store};
use tracing::debug;

use crate::v1beta1::{self, NodeAccessPolicy};

/// Returns a closure that maps a `NodeAccessPolicy` change to *every* PlaybookPlan, so their
/// managed-ssh node clamping is re-evaluated promptly when an admin edits a policy. A policy's
/// `namespaceSelector` can match any namespace, so without resolving namespace labels here (which a
/// sync mapper can't do) the safe mapping is "all plans" — plans are few and policy edits are rare.
pub fn node_access_policy_to_playbookplans(
    playbookplan_reader: Arc<Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(NodeAccessPolicy) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |policy| {
        playbookplan_reader
            .state()
            .iter()
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!(
                    "Reconcile of {} triggered by NodeAccessPolicy {}",
                    obj_ref,
                    policy.metadata.name.as_deref().unwrap_or("<unnamed>")
                )
            })
            .collect::<Vec<_>>()
    }
}

/// Returns a closure that maps a Secret to all PlaybookPlans that reference it.
///
/// # Panics
///
/// Panics if the secret returned from the apiserver does not have a name.
pub fn secret_to_playbookplans(
    secret_reflector_reader: Arc<kube::runtime::reflector::Store<v1beta1::PlaybookPlan>>,
) -> impl Fn(Secret) -> Vec<ObjectRef<v1beta1::PlaybookPlan>> {
    move |secret| {
        let secret_name = secret
            .metadata
            .name
            .as_deref()
            .expect("Secret must have a name");

        secret_reflector_reader
            .state()
            .iter()
            .filter(|resource| resource.metadata.namespace == secret.metadata.namespace)
            .filter(|plan| {
                if let Some(vars) = &plan.spec.template.variables
                    && vars.iter().any(|var| {
                        matches!(
                            var,
                            v1beta1::PlaybookVariableSource::SecretRef { secret_ref }
                            if secret_ref.name == secret_name
                        )
                    })
                {
                    return true;
                }

                if let Some(files) = &plan.spec.template.files {
                    return files.iter().any(|file| {
                        matches!(
                            file,
                            v1beta1::FilesSource::Secret { secret_ref, .. }
                            if secret_ref.name == secret_name
                        )
                    });
                }

                false
            })
            .map(|plan| ObjectRef::from(&**plan))
            .inspect(|obj_ref| {
                debug!(
                    "Reconcile of {} triggered by secret {}",
                    obj_ref, secret_name
                )
            })
            .collect::<Vec<_>>()
    }
}
