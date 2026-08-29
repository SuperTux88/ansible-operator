use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

use k8s_openapi::ByteString;

use crate::v1beta1::{self, distinct_hosts, renders_group_vars};

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct ExecutionHash(u64);

impl std::fmt::Display for ExecutionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl std::ops::Deref for ExecutionHash {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ExecutionHash {
    /// Reconstructs a persisted execution hash from its canonical lowercase hexadecimal form.
    pub fn from_hex(value: &str) -> Option<Self> {
        let parsed = u64::from_str_radix(value, 16).ok()?;
        (format!("{parsed:x}") == value).then_some(Self(parsed))
    }

    /// Folds inventory-author group variables into an existing hash. Kept separate from
    /// [`calculate_execution_hash`] so the many call sites that hash only playbook + secrets stay
    /// unchanged — the reconciler chains this on with the run's resolved groups.
    ///
    /// Inventory variables are treated as *content*: changing one re-applies the playbook to
    /// otherwise-current hosts. The fold is order-insensitive (groups resolve in arbitrary order),
    /// and an empty input is a no-op, so an inventory that sets no variables hashes exactly as it
    /// did before this field existed — see [`renders_group_vars`] for what counts as setting none.
    pub fn fold_inventory_variables<'a>(
        self,
        variables: impl IntoIterator<Item = (&'a str, &'a serde_json::Value)>,
    ) -> ExecutionHash {
        let extra = variables
            .into_iter()
            .filter(|(_, vars)| renders_group_vars(vars))
            .map(|(group_name, vars)| {
                let mut hasher = twox_hash::XxHash3_64::new();
                group_name.hash(&mut hasher);
                // serde_json's map is BTreeMap-backed (no `preserve_order` feature), so this
                // serialization is canonical: equal variable sets hash equal regardless of the
                // author's key order.
                serde_json::to_string(vars)
                    .unwrap_or_default()
                    .hash(&mut hasher);
                hasher.finish()
            })
            .fold(0u64, u64::wrapping_add);

        ExecutionHash(self.0.wrapping_add(extra))
    }
}

/// Returns an iterator over hosts where the PlaybookPlan needs to be (re)applied.
pub fn find_outdated_hosts(
    status: &v1beta1::PlaybookPlanStatus,
    execution_hash: &ExecutionHash,
) -> Vec<String> {
    let hosts = distinct_hosts(&status.eligible_hosts);

    // If we don't have any hosts_status yet, simply return all hosts for execution
    let Some(hosts_status) = &status.hosts_status else {
        return hosts;
    };

    let hash = execution_hash.to_string();
    // For each host, check if it already has the current execution hash in the PlaybookPlan's status
    let outdated_hosts = hosts.iter().filter(move |host| {
        let host_status = hosts_status.get(*host);

        // We don't have a status for this host yet so we must execute the playbook
        if host_status.is_none() {
            return true;
        }

        let host_status = host_status.unwrap();

        // Otherwise just compare the hashes
        host_status.last_applied_hash != hash
    });

    outdated_hosts.cloned().collect()
}

pub fn find_all_hosts(status: &v1beta1::PlaybookPlanStatus) -> Vec<String> {
    distinct_hosts(&status.eligible_hosts)
}

/// Given a playbook and some secrets, calculate a hash that only changes if the inputs change.
/// With regards to the secrets, the hash is order-insensitive.
pub fn calculate_execution_hash<'a, T: IntoIterator<Item = &'a BTreeMap<String, ByteString>>>(
    playbook: &str,
    secrets: T,
) -> ExecutionHash {
    let hash = std::iter::once({
        let mut hasher = twox_hash::XxHash3_64::new();
        playbook.hash(&mut hasher);
        hasher.finish()
    })
    .chain(secrets.into_iter().map(|secret| {
        let mut hasher = twox_hash::XxHash3_64::new();

        for (key, value) in secret {
            key.hash(&mut hasher);
            value.0.hash(&mut hasher);
        }

        hasher.finish()
    }))
    .fold(0u64, u64::wrapping_add);

    ExecutionHash(hash)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::v1beta1::{HostStatus, PlaybookPlanStatus, ResolvedHosts};

    use super::*;

    #[test]
    pub fn test_must_execute_returns_none_when_eligible_hosts_empty() {
        // Given
        let status = PlaybookPlanStatus {
            eligible_hosts: Vec::new(),
            ..Default::default()
        };

        // When
        let to_execute = find_outdated_hosts(&status, &ExecutionHash(1));

        // Then
        assert_eq!(to_execute.len(), 0);
    }

    #[test]
    pub fn test_must_execute_returns_all_when_hosts_status_empty() {
        // Given
        let status = PlaybookPlanStatus {
            eligible_hosts: vec![ResolvedHosts {
                name: "test-inventory".into(),
                hosts: vec!["host-1".into(), "host-2".into(), "host-3".into()],
            }],
            hosts_status: None,
            ..Default::default()
        };

        // When
        let to_execute = find_outdated_hosts(&status, &ExecutionHash(1));

        // Then
        let expected_hostnames = [
            "host-1".to_owned(),
            "host-2".to_owned(),
            "host-3".to_owned(),
        ];
        let expected: Vec<String> = expected_hostnames.to_vec();
        let actual: Vec<String> = to_execute;

        assert!(expected.eq(&actual));
    }

    #[test]
    pub fn test_must_execute_returns_correct_hosts() {
        // Given
        let status = PlaybookPlanStatus {
            eligible_hosts: vec![ResolvedHosts {
                name: "test-inventory".into(),
                hosts: vec!["host-1".into(), "host-2".into(), "host-3".into()],
            }],
            hosts_status: Some(BTreeMap::from_iter(vec![
                (
                    "host-1".to_owned(),
                    HostStatus {
                        last_applied_hash: "1".to_owned(),
                        ..Default::default()
                    },
                ),
                (
                    "host-2".to_owned(),
                    HostStatus {
                        last_applied_hash: "2".to_owned(),
                        ..Default::default()
                    },
                ),
                (
                    "host-3".to_owned(),
                    HostStatus {
                        last_applied_hash: "1".to_owned(),
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        };

        // When
        let to_execute = find_outdated_hosts(&status, &ExecutionHash(2));

        // Then
        let expected_hostnames = ["host-1".to_owned(), "host-3".to_owned()];
        let expected: Vec<String> = expected_hostnames.to_vec();
        let actual: Vec<String> = to_execute;

        assert_eq!(expected, actual);
    }

    #[test]
    pub fn test_calculate_execution_hash_is_order_insensitive() {
        // Given
        let playbook = "awesome playbook here";
        let secret1_data = BTreeMap::from_iter(vec![
            ("key-1".to_string(), ByteString(b"data-1".to_vec())),
            ("key-2".to_string(), ByteString(b"value-2".to_vec())),
        ]);
        let secret2_data = BTreeMap::from_iter(vec![(
            "meaningful_number".to_string(),
            ByteString(b"73".to_vec()),
        )]);
        let secret3_data = BTreeMap::from_iter(vec![(
            "answer".to_string(),
            ByteString(b"forty-two".to_vec()),
        )]);

        // When
        let hashed_1 =
            calculate_execution_hash(playbook, [&secret1_data, &secret2_data, &secret3_data]);
        let hashed_2 =
            calculate_execution_hash(playbook, [&secret2_data, &secret1_data, &secret3_data]);
        let hashed_3 =
            calculate_execution_hash(playbook, [&secret3_data, &secret2_data, &secret1_data]);

        // Then
        assert_eq!(hashed_1, hashed_2);
        assert_eq!(hashed_2, hashed_3);
    }

    #[test]
    pub fn test_fold_inventory_variables_changes_hash_and_is_order_insensitive() {
        let base = calculate_execution_hash("playbook", std::iter::empty());

        // No variables is a no-op, so pre-existing inventories keep their hash.
        assert_eq!(base, base.fold_inventory_variables(std::iter::empty()));

        let workers = serde_json::json!({ "ansible_python_interpreter": "/usr/bin/python3" });
        let edge = serde_json::json!({ "ansible_python_interpreter": "/usr/bin/python2" });

        let with_vars = base.fold_inventory_variables([("workers", &workers), ("edge", &edge)]);
        // Folding real variables changes the hash...
        assert_ne!(base, with_vars);
        // ...but the group order does not matter.
        assert_eq!(
            with_vars,
            base.fold_inventory_variables([("edge", &edge), ("workers", &workers)])
        );

        // A changed value changes the hash.
        let changed = serde_json::json!({ "ansible_python_interpreter": "/usr/bin/python3.11" });
        assert_ne!(
            with_vars,
            base.fold_inventory_variables([("workers", &changed), ("edge", &edge)])
        );
    }

    /// A group whose `variables` render nothing must hash as though it had none. The renderer emits
    /// a `vars:` block only for a non-empty mapping, so an author who adds `variables: {}` produces
    /// a byte-identical inventory — and a hash that moved for it would re-apply the playbook to
    /// every otherwise-current host for an edit no host can observe.
    #[test]
    fn a_group_whose_variables_render_nothing_hashes_as_though_it_had_none() {
        let base = calculate_execution_hash("playbook", std::iter::empty());
        let empty = serde_json::json!({});
        let real = serde_json::json!({ "motd": "hello" });

        assert_eq!(
            base.fold_inventory_variables([("workers", &empty)]),
            base,
            "an empty map is what the renderer drops, so it cannot move the hash"
        );
        assert_eq!(
            base.fold_inventory_variables([("workers", &real), ("edge", &empty)]),
            base.fold_inventory_variables([("workers", &real)]),
            "an empty map beside a real one contributes nothing either"
        );
        // Renaming a group that sets nothing is not a content change, because the group name is only
        // ever hashed as the key of variables that exist.
        assert_eq!(
            base.fold_inventory_variables([("edge", &empty)]),
            base.fold_inventory_variables([("workers", &empty)])
        );
    }

    /// The predicate is the renderer's, so it has to answer for the shapes the renderer refuses —
    /// not merely for the empty map. Nothing but an object can reach `variables` through the CRD,
    /// but the hash must not be the one place that disagrees if one ever did.
    #[test]
    fn only_a_non_empty_mapping_counts_as_group_variables() {
        assert!(renders_group_vars(&serde_json::json!({ "a": 1 })));

        assert!(!renders_group_vars(&serde_json::json!({})));
        assert!(!renders_group_vars(&serde_json::Value::Null));
        assert!(!renders_group_vars(&serde_json::json!([1, 2])));
        assert!(!renders_group_vars(&serde_json::json!("a string")));
    }

    /// A node reachable through two inventory groups is one host everywhere the plan counts or
    /// lists hosts. The counts feed the `n/m` summary and the restated `Ready` message, which sit
    /// beside a `Play`'s own always-distinct `Hosts` column, and the lists feed `filter_groups_to_hosts`.
    #[test]
    fn a_host_in_two_groups_counts_and_lists_once() {
        let overlapping = vec![
            ResolvedHosts {
                name: "workers".into(),
                hosts: vec!["node-a".into(), "node-b".into()],
            },
            ResolvedHosts {
                name: "storage".into(),
                hosts: vec!["node-b".into(), "node-c".into()],
            },
        ];
        assert_eq!(
            distinct_hosts(&overlapping),
            vec!["node-a".to_string(), "node-b".into(), "node-c".into()],
            "first-seen order, so group membership still reads naturally"
        );
        assert_eq!(crate::v1beta1::distinct_host_count(&overlapping), 3);

        let hash = ExecutionHash(1);
        let mut status = PlaybookPlanStatus {
            eligible_hosts: overlapping,
            ..Default::default()
        };
        assert_eq!(find_all_hosts(&status).len(), 3);
        assert_eq!(
            find_outdated_hosts(&status, &hash).len(),
            3,
            "a plan that never ran owes each host one run, not one per group it appears in"
        );

        status.hosts_status = Some(BTreeMap::from([(
            "node-b".to_string(),
            HostStatus {
                last_applied_hash: hash.to_string(),
                ..Default::default()
            },
        )]));
        assert_eq!(
            find_outdated_hosts(&status, &hash),
            vec!["node-a".to_string(), "node-c".into()],
            "the shared host is current once, not once per group"
        );
    }

    #[test]
    pub fn test_execution_hash_display() {
        // Given
        let hash = ExecutionHash(255);

        // When
        let as_string = hash.to_string();

        // Then
        assert_eq!("ff", as_string)
    }
}
