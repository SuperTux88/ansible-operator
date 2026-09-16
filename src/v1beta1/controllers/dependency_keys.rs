//! The Node label key a plan publishes its `spec.provides` version under, and its inverse.
//!
//! Shared vocabulary between two controllers rather than a detail of either. The plan controller
//! *writes* `<namespace>.plan.ansible.cloudbending.dev/<plan-name>` onto the Nodes a providing plan
//! converged (`playbookplancontroller::node_labels`); the inventory controller *reads* the same key
//! out of a tenant's selector to tell a dependency on another plan from an ordinary label term
//! (`clusterinventorycontroller::dependencies`). Both ends have to agree on the format exactly — one
//! recognising a key the other would not produce is a dependency nobody is told about.
//!
//! The operator owns the key: it is derived from the plan's own namespace and name, never from
//! anything a tenant writes. A tenant-chosen key would let a plan label its way past a
//! `NodeAccessPolicy` ceiling, steer other people's workloads through a well-known key, or overwrite
//! another plan's claim (INV-8, THREAT_MODEL T-ESC-3/T-ESC-9).

/// The domain every operator-owned Node label key ends its prefix with.
///
/// A label key holds at most one `/`, separating the optional DNS-subdomain prefix from the name,
/// and the name may not contain one — so a key *containing* `".plan.ansible.cloudbending.dev/"` has
/// a prefix ending in this domain, whatever namespace and plan name it encodes. That is what lets
/// the operator recognise its own keys with a substring test rather than a parse. The chart's
/// `ValidatingAdmissionPolicy` matches on the same string; the test at the bottom of this file pins
/// the two together.
pub const KEY_DOMAIN: &str = ".plan.ansible.cloudbending.dev";

/// The label key a plan publishes under: `<namespace>.plan.ansible.cloudbending.dev/<plan-name>`.
///
/// Always within Kubernetes' limits by construction, so this cannot produce a key the API server
/// would reject: a namespace is at most 63 characters, which leaves the prefix at most 93 of the
/// 253 allowed, and a plan name is capped at 63 — the label *name* limit — by `MAX_PLAN_NAME_LEN`
/// and its CRD rule, which the reconciler refuses a plan for before it ever reaches this.
pub fn label_key(namespace: &str, plan: &str) -> String {
    format!("{namespace}{KEY_DOMAIN}/{plan}")
}

/// Whether `key` is one this operator manages, for any namespace and any plan.
pub fn is_operator_key(key: &str) -> bool {
    key.contains(&format!("{KEY_DOMAIN}/"))
}

/// The namespace and plan name an operator-owned key encodes, or `None` for any other key.
///
/// The inverse of [`label_key`], and the reason a key carries both: a label found on a Node names
/// the plan that must still exist for it to be legitimate, without the operator having to keep a
/// record of what it wrote. It is also what lets a dependent's diagnostics name the provider it is
/// waiting for without looking anything up.
pub fn decode_key(key: &str) -> Option<(&str, &str)> {
    let (prefix, plan) = key.split_once('/')?;
    let namespace = prefix.strip_suffix(KEY_DOMAIN)?;

    (!namespace.is_empty() && !plan.is_empty()).then_some((namespace, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "platform.plan.ansible.cloudbending.dev/containerd";

    #[test]
    fn a_key_decodes_back_to_the_plan_that_wrote_it() {
        assert_eq!(decode_key(KEY), Some(("platform", "containerd")));
        assert_eq!(
            decode_key(&label_key("team-a", "harden")),
            Some(("team-a", "harden"))
        );

        assert_eq!(decode_key("node-role.kubernetes.io/worker"), None);
        assert_eq!(
            decode_key("plan.ansible.cloudbending.dev/x"),
            None,
            "the namespace segment and its dot are part of the format"
        );
        assert_eq!(
            decode_key("a.plan.ansible.cloudbending.dev.evil/x"),
            None,
            "the domain has to end the prefix, not merely appear in it"
        );
        assert!(is_operator_key(KEY));
        assert!(!is_operator_key("node-role.kubernetes.io/worker"));
    }

    /// The chart's `ValidatingAdmissionPolicy` matches the operator's keys with the same string this
    /// module builds them from. They are in different languages and different files, so nothing but
    /// a test keeps them together — and a drift would either strip the guard of its meaning or have
    /// the API server reject every label the operator writes.
    #[test]
    fn the_admission_policy_matches_the_key_this_module_builds() {
        let policy = include_str!("../../../chart/templates/validatingadmissionpolicy.yaml");
        let matcher = format!("key.contains(\"{KEY_DOMAIN}/\")");

        assert!(
            policy.contains(&matcher),
            "the chart policy must test for {matcher}"
        );
    }
}
