//! Which of a group's Nodes are kept out by another plan, rather than by the group's own selector.
//!
//! An inventory that gates itself on a dependency label resolves fewer hosts than its author wrote
//! it for, on purpose and temporarily. From the outside that is indistinguishable from a typo in the
//! key, a selector that matches nothing, or a provider that will never run — every one of them looks
//! like "my inventory has three hosts and I expected eight". This is what tells them apart: for each
//! requirement on a key this operator publishes, how many of the group's Nodes are held back by it
//! and how many have already got past it.
//!
//! Two properties are load-bearing:
//!
//! - **The same evaluator decides both.** Every term is judged by `nodeselector`'s own
//!   `eval_expression`/`eval_match_label`, never by a second implementation here. A diagnostic that
//!   disagreed with the matching it explains would be worse than none.
//! - **Waiting is measured against the group as its author wrote it**, which is every term that is
//!   not itself a dependency. A Node excluded for an unrelated reason — the wrong `node-role`, a
//!   `NotIn` — is not waiting for anything, it is simply not this group's Node, and counting it
//!   would bury the machines that really are one run away from joining. A Node held back by two
//!   dependencies is waiting for both, since neither finishing releases it on its own.
//!
//! Nothing here looks a provider plan up. The key names one, and that is the whole message: a
//! dependency on a plan nobody has reads as waiting for it, which is what a typo looks like anyway.

use k8s_openapi::api::core::v1::Node;
use kube::ResourceExt as _;
use kube::api::PartialObjectMeta;
use std::collections::BTreeMap;

use crate::v1beta1::controllers::dependency_keys::{decode_key, is_operator_key};
use crate::v1beta1::controllers::nodeselector::{eval_expression, eval_match_label};
use crate::v1beta1::controllers::version;
use crate::v1beta1::{DependencyStatus, NodeSelectorTerm, SelectorExpression, SelectorOperator};

/// The most requirements one inventory publishes in `status.dependencies`.
///
/// This and [`MAX_FIELD_CHARS`] are what keep the status under the apiserver's object size limit
/// whatever the spec says. Every entry copies its group name, key and values out of the spec, once
/// per requirement, so a spec well within the limit could otherwise produce a status past it. That
/// write would then fail on every tick, `observedGeneration` would never advance, and every plan
/// naming the inventory would wait on `InventoryNotSynced` for good, renewing the host Leases of
/// any run it was holding.
///
/// Far above any real inventory. Beyond it the entries are dropped rather than the write, so the
/// hosts are still published and `waitingHosts` stays exact.
pub const MAX_DEPENDENCIES: usize = 256;

/// The most characters a string in a `status.dependencies` entry keeps — the length of the longest
/// valid label key, and therefore of any key a Node could actually carry. A longer string is cut
/// and ends in `…`.
pub const MAX_FIELD_CHARS: usize = 317;

fn bounded(text: &str) -> String {
    match text.char_indices().nth(MAX_FIELD_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// What one group's selector is waiting on, and which of its Nodes are waiting.
#[derive(Debug, Default, PartialEq)]
pub struct GroupDependencies {
    /// One entry per dependency requirement in the group's selector, in the order they are written.
    pub dependencies: Vec<DependencyStatus>,
    /// The Nodes kept out of this group by a dependency alone, named so the caller can count
    /// distinct hosts across groups. A Node waiting on two requirements appears once.
    pub waiting_hosts: Vec<String>,
}

/// One requirement of a group's selector, whichever half of the selector wrote it.
///
/// `matchLabels` entries and `matchExpressions` terms are the same thing to this analysis — a
/// condition a Node passes or fails — and both can name an operator-owned key.
enum Term<'a> {
    Equals { key: &'a str, value: &'a str },
    Expression(&'a SelectorExpression),
}

impl Term<'_> {
    fn key(&self) -> &str {
        match self {
            Term::Equals { key, .. } => key,
            Term::Expression(expr) => &expr.key,
        }
    }

    fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self {
            Term::Equals { key, value } => eval_match_label(labels, key, value),
            Term::Expression(expr) => eval_expression(labels, expr),
        }
    }

    /// Whether this term waits for a provider, as opposed to merely selecting on a label.
    ///
    /// A dependency is a **positive** requirement on a key this operator publishes. `NotIn` and
    /// `DoesNotExist` are exclusions: a Node fails them by *carrying* something, and no provider
    /// finishing will change that, so they are ordinary terms however the key is spelled.
    ///
    /// Matched exhaustively on purpose. A new operator added to [`SelectorOperator`] has to be
    /// placed on one side of that line deliberately; a catch-all would silently file it under "not a
    /// dependency" and lose every wait it expresses.
    fn is_dependency(&self) -> bool {
        if !is_operator_key(self.key()) {
            return false;
        }

        match self {
            Term::Equals { .. } => true,
            Term::Expression(expr) => match expr.operator {
                SelectorOperator::In
                | SelectorOperator::Exists
                | SelectorOperator::Gt
                | SelectorOperator::Ge
                | SelectorOperator::Lt
                | SelectorOperator::Le => true,
                SelectorOperator::NotIn | SelectorOperator::DoesNotExist => false,
            },
        }
    }

    /// The single value an ordered comparison is made against, or `None` for every other term and
    /// for an ordered term that does not list exactly one.
    fn ordered_bound(&self) -> Option<&str> {
        let Term::Expression(expr) = self else {
            return None;
        };
        match expr.operator {
            SelectorOperator::Gt
            | SelectorOperator::Ge
            | SelectorOperator::Lt
            | SelectorOperator::Le => match expr.values.as_deref() {
                Some([bound]) => Some(bound),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_ordered(&self) -> bool {
        matches!(
            self,
            Term::Expression(SelectorExpression {
                operator: SelectorOperator::Gt
                    | SelectorOperator::Ge
                    | SelectorOperator::Lt
                    | SelectorOperator::Le,
                ..
            })
        )
    }

    /// A term that can match nothing because of how it is written: an ordered operator not listing
    /// exactly one value, or an `In` listing none.
    fn is_malformed(&self) -> bool {
        match self {
            Term::Expression(expr) if expr.operator == SelectorOperator::In => {
                expr.values.as_deref().is_none_or(<[String]>::is_empty)
            }
            _ => self.is_ordered() && self.ordered_bound().is_none(),
        }
    }

    /// The requirement written back for a human, in the shape the selector used.
    fn render(&self) -> String {
        match self {
            Term::Equals { value, .. } => format!("= {value}"),
            Term::Expression(expr) => {
                let operator = format!("{:?}", expr.operator);
                match (&expr.operator, expr.values.as_deref()) {
                    (SelectorOperator::Exists | SelectorOperator::DoesNotExist, _) => operator,
                    // A single value reads as the comparison it is; anything else is rendered as the
                    // list it actually is, so a malformed ordered term shows what is wrong with it.
                    (_, Some([value])) if self.is_ordered() => format!("{operator} {value}"),
                    (_, Some(values)) => format!("{operator} [{}]", values.join(", ")),
                    (_, None) => format!("{operator} []"),
                }
            }
        }
    }
}

/// Splits a group's selector into its requirements and counts what each is holding back.
///
/// Pure, and the whole decision — the controller only publishes what this returns.
///
/// `selector` is the group's flattened `NodeSelectorTerm`, exactly as `node_matches` is handed it,
/// so it carries both `matchLabels` and `matchExpressions`. A group with no selector at all matches
/// every Node and depends on nothing.
///
/// One pass per Node: every term is evaluated once, and each requirement's answer is then read off
/// that row. A Node counts towards a requirement only when it passes every term that is *not* a
/// dependency, which is what separates "not yet" from "not yours" — and `satisfied + waiting` is
/// then the same denominator for every requirement of the group, which is what makes "3 of 8"
/// readable.
pub fn waits(
    group: &str,
    selector: Option<&NodeSelectorTerm>,
    nodes: &[PartialObjectMeta<Node>],
) -> GroupDependencies {
    let Some(selector) = selector else {
        return GroupDependencies::default();
    };

    let terms: Vec<Term> = selector
        .match_labels
        .iter()
        .flatten()
        .map(|(key, value)| Term::Equals { key, value })
        .chain(
            selector
                .match_expressions
                .iter()
                .flatten()
                .map(Term::Expression),
        )
        .collect();

    let dependencies: Vec<usize> = terms
        .iter()
        .enumerate()
        .filter(|(_, term)| term.is_dependency())
        .map(|(index, _)| index)
        .collect();
    if dependencies.is_empty() {
        return GroupDependencies::default();
    }

    let mut counts = vec![(0usize, 0usize, 0usize); terms.len()];
    let mut waiting_hosts = Vec::new();

    for node in nodes {
        let labels = node.labels();
        let verdicts: Vec<bool> = terms.iter().map(|term| term.matches(labels)).collect();
        // The group as its author meant it, before any dependency narrows it: every term that is
        // *not* a wait. A Node failing one of those is not this group's Node at all, and counting it
        // as waiting would bury the machines that really are one run away from joining.
        //
        // Other dependencies deliberately do not count here. A Node held back by two of them is
        // waiting for both — neither finishing releases it, and there is no reason to prefer one —
        // so "3 waiting for A, 3 waiting for B" is the honest statement about the same 3 machines.
        let in_group = verdicts
            .iter()
            .enumerate()
            .all(|(index, matched)| *matched || dependencies.contains(&index));
        if !in_group {
            continue;
        }
        let mut waits_here = false;

        for &index in &dependencies {
            let (waiting, satisfied, unparseable) = &mut counts[index];
            if verdicts[index] {
                *satisfied += 1;
                continue;
            }

            *waiting += 1;
            waits_here = true;
            // The provider's own doing rather than the selector's: it published a value no ordered
            // comparison can answer, so this Node waits for ever and nothing about the selector
            // says why.
            if terms[index].is_ordered()
                && labels
                    .get(terms[index].key())
                    .is_some_and(|value| version::parse(value).is_none())
            {
                *unparseable += 1;
            }
        }

        if waits_here && let Some(name) = node.metadata.name.clone() {
            waiting_hosts.push(name);
        }
    }

    GroupDependencies {
        dependencies: dependencies
            .iter()
            .map(|&index| {
                let term = &terms[index];
                let key = term.key();
                // A key only the substring test accepts, such as `.plan.ansible.cloudbending.dev/x`,
                // names no plan. It is still a wait, and most likely a typo, so the raw key stands
                // in for the provider rather than an empty name nobody could trace back.
                let (namespace, plan) = decode_key(key).unwrap_or(("", key));
                let (waiting, satisfied, unparseable_hosts) = counts[index];

                DependencyStatus {
                    group: bounded(group),
                    key: bounded(key),
                    provider_namespace: bounded(namespace),
                    provider_name: bounded(plan),
                    requirement: bounded(&term.render()),
                    waiting,
                    satisfied,
                    invalid_value: term
                        .ordered_bound()
                        .is_some_and(|bound| version::parse(bound).is_none()),
                    malformed_term: term.is_malformed(),
                    unparseable_hosts,
                }
            })
            .collect(),
        waiting_hosts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1beta1::controllers::dependency_keys::label_key;
    use kube::Resource as _;

    fn node(name: &str, labels: &[(&str, &str)]) -> PartialObjectMeta<Node> {
        let mut object = Node::default();
        object.metadata.name = Some(name.to_string());
        object.metadata.labels = Some(
            labels
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        );
        PartialObjectMeta {
            metadata: object.meta().clone(),
            ..Default::default()
        }
    }

    fn expression(key: &str, operator: SelectorOperator, values: &[&str]) -> SelectorExpression {
        SelectorExpression {
            operator,
            key: key.to_string(),
            values: Some(values.iter().map(|value| (*value).to_string()).collect()),
        }
    }

    fn selector(labels: &[(&str, &str)], expressions: Vec<SelectorExpression>) -> NodeSelectorTerm {
        NodeSelectorTerm {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
            ),
            match_expressions: Some(expressions),
        }
    }

    fn containerd() -> String {
        label_key("platform", "containerd")
    }

    /// The shape the whole feature is for: a provider partway through its fleet, and an inventory
    /// that says how far it has got rather than silently resolving to half its hosts.
    #[test]
    fn a_node_failing_only_the_dependency_is_waiting() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[("node-role", "worker")],
                vec![expression(&key, SelectorOperator::Ge, &["1.4.0"])],
            )),
            &[
                node("ready", &[("node-role", "worker"), (&key, "1.4.2")]),
                node("behind", &[("node-role", "worker"), (&key, "1.3.0")]),
                node("bare", &[("node-role", "worker")]),
            ],
        );

        let dependency = &result.dependencies[0];
        assert_eq!(dependency.key, key);
        assert_eq!(dependency.provider_namespace, "platform");
        assert_eq!(dependency.provider_name, "containerd");
        assert_eq!(dependency.requirement, "Ge 1.4.0");
        assert_eq!(dependency.satisfied, 1);
        assert_eq!(dependency.waiting, 2);
        assert_eq!(result.waiting_hosts, vec!["behind", "bare"]);
    }

    /// The point of measuring against the rest of the group: a Node that is not this group's Node at
    /// all must not be reported as one run away from joining it.
    #[test]
    fn a_node_failing_an_unrelated_term_is_not_waiting() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[("node-role", "worker")],
                vec![expression(&key, SelectorOperator::Exists, &[])],
            )),
            &[node("controlplane", &[("node-role", "control-plane")])],
        );

        assert_eq!(result.dependencies[0].waiting, 0);
        assert_eq!(result.dependencies[0].satisfied, 0);
        assert!(result.waiting_hosts.is_empty());
    }

    /// Neither dependency is preferred, because neither one finishing releases the Node on its own.
    #[test]
    fn a_node_failing_two_dependencies_is_counted_under_both() {
        let containerd = containerd();
        let hardening = label_key("platform", "hardening");
        let result = waits(
            "workers",
            Some(&selector(
                &[],
                vec![
                    expression(&containerd, SelectorOperator::Exists, &[]),
                    expression(&hardening, SelectorOperator::Exists, &[]),
                ],
            )),
            &[node("bare", &[])],
        );

        assert_eq!(result.dependencies.len(), 2);
        assert!(result.dependencies.iter().all(|entry| entry.waiting == 1));
        assert_eq!(
            result.waiting_hosts,
            vec!["bare"],
            "one Node, however many requirements it fails"
        );
    }

    /// `satisfied + waiting` is the denominator, so both are published rather than one number.
    #[test]
    fn satisfied_and_waiting_add_up_to_the_group_less_its_other_terms() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[("node-role", "worker")],
                vec![expression(&key, SelectorOperator::Exists, &[])],
            )),
            &[
                node("a", &[("node-role", "worker"), (&key, "1.0")]),
                node("b", &[("node-role", "worker")]),
                node("c", &[("node-role", "control-plane")]),
            ],
        );

        let dependency = &result.dependencies[0];
        assert_eq!(dependency.satisfied + dependency.waiting, 2);
    }

    /// Equality counts as a dependency whichever half of the selector writes it, since both express
    /// exactly the same wait.
    #[test]
    fn equality_on_an_operator_key_is_a_dependency() {
        let key = containerd();
        let from_match_labels = waits(
            "workers",
            Some(&selector(&[(&key, "1.4.2")], vec![])),
            &[node("a", &[(&key, "1.4.2")]), node("b", &[])],
        );
        let from_expressions = waits(
            "workers",
            Some(&selector(
                &[],
                vec![expression(&key, SelectorOperator::In, &["1.4.2"])],
            )),
            &[node("a", &[(&key, "1.4.2")]), node("b", &[])],
        );

        assert_eq!(from_match_labels.dependencies[0].requirement, "= 1.4.2");
        assert_eq!(from_match_labels.dependencies[0].waiting, 1);
        assert_eq!(from_expressions.dependencies[0].requirement, "In [1.4.2]");
        assert_eq!(from_expressions.dependencies[0].waiting, 1);
    }

    /// An exclusion is not a wait: the Node fails it by carrying something, and no provider
    /// finishing takes that away.
    #[test]
    fn exclusions_and_foreign_keys_are_ordinary_terms() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[("node-role", "worker")],
                vec![
                    expression(&key, SelectorOperator::NotIn, &["1.0"]),
                    expression(&key, SelectorOperator::DoesNotExist, &[]),
                    expression("topology.kubernetes.io/zone", SelectorOperator::Exists, &[]),
                ],
            )),
            &[node("a", &[])],
        );

        assert!(result.dependencies.is_empty());
        assert!(result.waiting_hosts.is_empty());
    }

    /// A selector value that is not a version matches nothing, so the whole group waits on it. The
    /// count is the symptom and the flag is the cause.
    #[test]
    fn an_unparseable_selector_value_is_flagged() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[],
                vec![expression(&key, SelectorOperator::Ge, &["latest"])],
            )),
            &[node("a", &[(&key, "1.4.2")])],
        );

        let dependency = &result.dependencies[0];
        assert!(dependency.invalid_value);
        assert!(!dependency.malformed_term);
        assert_eq!(dependency.waiting, 1);
        assert_eq!(dependency.requirement, "Ge latest");
    }

    /// The case admission deliberately does not reject, so these diagnostics are the only thing
    /// standing between it and a selector that silently matches nothing.
    #[test]
    fn an_ordered_term_without_exactly_one_value_is_flagged() {
        let key = containerd();
        for values in [vec![], vec!["1.0", "2.0"]] {
            let result = waits(
                "workers",
                Some(&selector(
                    &[],
                    vec![expression(&key, SelectorOperator::Ge, &values)],
                )),
                &[node("a", &[(&key, "1.4.2")])],
            );

            let dependency = &result.dependencies[0];
            assert!(dependency.malformed_term, "{values:?} is not a comparison");
            assert!(
                !dependency.invalid_value,
                "the term has no single value to judge"
            );
            assert_eq!(dependency.waiting, 1);
        }
    }

    /// The one failure the label's author caused: a provider that published `latest` leaves its
    /// dependents waiting for ever with nothing wrong in their own selector.
    #[test]
    fn a_node_carrying_a_value_that_is_not_a_version_is_flagged() {
        let key = containerd();
        let result = waits(
            "workers",
            Some(&selector(
                &[],
                vec![expression(&key, SelectorOperator::Ge, &["1.4.0"])],
            )),
            &[
                node("odd", &[(&key, "latest")]),
                node("behind", &[(&key, "1.0.0")]),
                node("bare", &[]),
            ],
        );

        let dependency = &result.dependencies[0];
        assert_eq!(dependency.waiting, 3);
        assert_eq!(
            dependency.unparseable_hosts, 1,
            "a Node that simply has no label carries no unparseable value"
        );
    }

    /// The spec bounds none of these strings, and every requirement copies them, so the status
    /// cuts them instead of growing past the object size limit (see [`MAX_DEPENDENCIES`]).
    #[test]
    fn long_strings_are_cut_in_the_status() {
        let key = containerd();
        let many: Vec<String> = (0..200).map(|index| format!("1.{index}.0")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let group = "g".repeat(1000);

        let result = waits(
            &group,
            Some(&selector(
                &[],
                vec![expression(&key, SelectorOperator::In, &many)],
            )),
            &[],
        );

        let dependency = &result.dependencies[0];
        assert_eq!(dependency.requirement.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(dependency.requirement.starts_with("In [1.0.0, 1.1.0, "));
        assert!(dependency.requirement.ends_with('…'));
        assert_eq!(dependency.group.chars().count(), MAX_FIELD_CHARS + 1);
        assert_eq!(
            dependency.key, key,
            "a key short enough to be a label is kept whole"
        );
    }

    #[test]
    fn a_string_is_cut_on_a_character_boundary() {
        let text = "ä".repeat(MAX_FIELD_CHARS + 5);
        assert_eq!(bounded(&text), format!("{}…", "ä".repeat(MAX_FIELD_CHARS)));
        assert_eq!(bounded("short"), "short");
        assert_eq!(
            bounded(&"a".repeat(MAX_FIELD_CHARS)),
            "a".repeat(MAX_FIELD_CHARS)
        );
    }

    /// `In` with no values matches nothing, like an ordered term with none, and without the flag
    /// its `waiting` would read as a provider that is not converging.
    #[test]
    fn an_in_listing_no_values_is_flagged() {
        let key = containerd();
        for values in [None, Some(Vec::new())] {
            let result = waits(
                "workers",
                Some(&selector(
                    &[],
                    vec![SelectorExpression {
                        operator: SelectorOperator::In,
                        key: key.clone(),
                        values,
                    }],
                )),
                &[node("bare", &[])],
            );
            assert!(result.dependencies[0].malformed_term);
        }

        let listed = waits(
            "workers",
            Some(&selector(
                &[],
                vec![expression(&key, SelectorOperator::In, &["1.4.0"])],
            )),
            &[],
        );
        assert!(!listed.dependencies[0].malformed_term);
    }

    /// A key the substring test accepts but that decodes to no plan is the likeliest typo of all, so
    /// it is reported under its own spelling rather than as a wait for `/`.
    #[test]
    fn a_key_naming_no_plan_is_reported_by_its_spelling() {
        let key = ".plan.ansible.cloudbending.dev/x";
        let result = waits(
            "workers",
            Some(&selector(
                &[],
                vec![expression(key, SelectorOperator::Exists, &[])],
            )),
            &[],
        );

        let dependency = &result.dependencies[0];
        assert_eq!(dependency.provider_namespace, "");
        assert_eq!(dependency.provider_name, key);
    }

    /// A diagnostic where there is nothing to diagnose is noise, and an inventory without
    /// dependencies is the overwhelmingly common one.
    #[test]
    fn a_selector_without_operator_keys_reports_nothing() {
        let result = waits(
            "workers",
            Some(&selector(&[("node-role", "worker")], vec![])),
            &[node("a", &[("node-role", "worker")])],
        );

        assert_eq!(result, GroupDependencies::default());
        assert_eq!(
            waits("all", None, &[node("a", &[])]),
            GroupDependencies::default()
        );
    }
}
