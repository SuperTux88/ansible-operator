use std::fmt::Debug;

use chrono::{DateTime, FixedOffset};
use kube::api::{Patch, PatchParams, PostParams};
use serde::{Serialize, de::DeserializeOwned};

/// RFC 1123 *label* cap. Bounds every label **value**, and the names of the objects Kubernetes
/// requires to be DNS labels — Jobs and NetworkPolicies among them.
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// RFC 1123 *subdomain* cap used by resource-name budget tests.
#[cfg(test)]
pub const MAX_DNS_SUBDOMAIN_LEN: usize = 253;

pub async fn create_or_update<K>(
    api: &kube::Api<K>,
    field_manager: &str,
    resource_name: &str,
    resource: K,
    mutate_fn: impl FnOnce(K, &mut K),
) -> Result<(), kube::Error>
where
    K: DeserializeOwned + Serialize + Clone + Debug,
{
    if let Some(existing_resource) = api.get_opt(resource_name).await? {
        let mut updated_resource = resource.clone();
        mutate_fn(existing_resource, &mut updated_resource);

        api.patch(
            resource_name,
            &PatchParams::apply(field_manager),
            &Patch::Apply(&updated_resource),
        )
        .await?;
    } else {
        api.create(
            &PostParams {
                field_manager: Some(field_manager.into()),
                ..Default::default()
            },
            &resource,
        )
        .await?;
    }

    Ok(())
}

pub trait Condition {
    fn type_(&self) -> &str;
    fn status(&self) -> &str;
    fn reason(&self) -> Option<&str>;
    fn message(&self) -> Option<&str>;
    fn last_transition_time(&self) -> Option<DateTime<FixedOffset>>;
    fn set_last_transition_time(&mut self, value: Option<DateTime<FixedOffset>>);
}

/// Replaces the condition of the same `type` with `new_condition`, or appends it.
///
/// The message is part of what makes two conditions different. Several conditions keep one reason
/// across changing detail — `Blocked` names the contended host, `WaitingForNodes` the pending nodes,
/// `Ready`/`InputsUnavailable` the read that failed and `Ready`/`AllHostsSucceeded` the host tally —
/// so comparing only `status` and `reason` would pin the first message of a run for the whole of it,
/// and leave the condition contradicting the `.status.summary` written from the same diagnostic.
///
/// `lastTransitionTime` still marks the last time the **status** changed, which is what the name
/// promises and what a reader ages a stuck condition by. A condition that only restates itself with
/// a fresher message therefore keeps the timestamp it already had.
pub fn upsert_condition<T: Condition>(conditions: &mut Vec<T>, mut new_condition: T) {
    if let Some(existing_condition) = conditions
        .iter_mut()
        .find(|c| c.type_() == new_condition.type_())
    {
        let status_unchanged = existing_condition.status() == new_condition.status();

        // Skip change if we can't see a difference in the new value
        if status_unchanged
            && existing_condition.reason() == new_condition.reason()
            && existing_condition.message() == new_condition.message()
        {
            return;
        }

        if status_unchanged {
            new_condition.set_last_transition_time(existing_condition.last_transition_time());
        }

        *existing_condition = new_condition;
    } else {
        conditions.push(new_condition);
    }
}

fn encode_kubelike(mut num: u64) -> String {
    const ALPHABET: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";

    if num == 0 {
        return "a".repeat(6); // return "aaaaaa" if input is zero, fixed length
    }
    let base = ALPHABET.len() as u64;
    let mut chars = Vec::new();

    while num > 0 {
        let rem = (num % base) as usize;
        chars.push(ALPHABET[rem] as char);
        num /= base;
    }

    chars.reverse();
    chars.into_iter().collect()
}

/// Generate a short Kubernetes-like ID for use in resource names
pub fn generate_id(num: u64) -> String {
    generate_id_with_length(num, 5)
}

/// [`generate_id`] with an explicit length, for IDs that need more of `num`'s entropy than a name
/// suffix does. The alphabet has 27 symbols, so `length` caps out at 14 (a full `u64`); anything
/// longer is just zero-padding.
pub fn generate_id_with_length(num: u64, length: usize) -> String {
    let encoded = encode_kubelike(num);

    if encoded.len() == length {
        encoded
    } else if encoded.len() > length {
        encoded[encoded.len() - length..].to_string()
    } else {
        let padding = "a".repeat(length - encoded.len());
        format!("{padding}{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCondition {
        type_: &'static str,
        status: &'static str,
        reason: Option<&'static str>,
        message: Option<&'static str>,
        last_transition_time: Option<DateTime<FixedOffset>>,
    }

    impl Condition for TestCondition {
        fn type_(&self) -> &str {
            self.type_
        }

        fn status(&self) -> &str {
            self.status
        }

        fn reason(&self) -> Option<&str> {
            self.reason
        }

        fn message(&self) -> Option<&str> {
            self.message
        }

        fn last_transition_time(&self) -> Option<DateTime<FixedOffset>> {
            self.last_transition_time
        }

        fn set_last_transition_time(&mut self, value: Option<DateTime<FixedOffset>>) {
            self.last_transition_time = value;
        }
    }

    fn at(timestamp: &str) -> Option<DateTime<FixedOffset>> {
        Some(DateTime::parse_from_rfc3339(timestamp).unwrap())
    }

    fn ready(
        status: &'static str,
        reason: Option<&'static str>,
        message: Option<&'static str>,
        timestamp: &str,
    ) -> TestCondition {
        TestCondition {
            type_: "Ready",
            status,
            reason,
            message,
            last_transition_time: at(timestamp),
        }
    }

    fn sole(conditions: &[TestCondition]) -> &TestCondition {
        assert_eq!(
            conditions.len(),
            1,
            "the condition is replaced, not appended"
        );
        &conditions[0]
    }

    /// The reason a condition carries a message at all: it names *which* instance of a recurring
    /// reason is current. Restating it is not a transition, though, so the timestamp a reader ages
    /// the condition by has to survive the update.
    #[test]
    fn a_new_message_under_an_unchanged_status_replaces_it_without_transitioning() {
        let mut conditions = vec![ready(
            "False",
            Some("InputsUnavailable"),
            Some("first failure"),
            "2026-08-26T10:00:00+02:00",
        )];

        upsert_condition(
            &mut conditions,
            ready(
                "False",
                Some("InputsUnavailable"),
                Some("second failure"),
                "2026-08-26T11:00:00+02:00",
            ),
        );

        let condition = sole(&conditions);
        assert_eq!(condition.message, Some("second failure"));
        assert_eq!(
            condition.last_transition_time,
            at("2026-08-26T10:00:00+02:00"),
            "the status did not change, so this is not a transition"
        );
    }

    /// The other half of the same rule, and the one the caller depends on for the printer column:
    /// a status that *does* change carries the new condition's own timestamp.
    #[test]
    fn a_changed_status_transitions_to_the_new_timestamp() {
        let mut conditions = vec![ready(
            "False",
            Some("HostsOutdated"),
            Some("1/2 hosts on the current revision"),
            "2026-08-26T10:00:00+02:00",
        )];

        upsert_condition(
            &mut conditions,
            ready(
                "True",
                Some("HostsUpToDate"),
                Some("2/2 hosts on the current revision"),
                "2026-08-26T11:00:00+02:00",
            ),
        );

        let condition = sole(&conditions);
        assert_eq!(condition.status, "True");
        assert_eq!(
            condition.last_transition_time,
            at("2026-08-26T11:00:00+02:00")
        );
    }

    /// A condition that says exactly what the stored one already says is not written at all — every
    /// setter runs on every tick, so this is what keeps an unchanged plan from patching its status
    /// in a loop.
    #[test]
    fn an_identical_condition_is_left_untouched() {
        let mut conditions = vec![ready(
            "True",
            Some("JobRunning"),
            Some("the run's Job is still active"),
            "2026-08-26T10:00:00+02:00",
        )];

        upsert_condition(
            &mut conditions,
            ready(
                "True",
                Some("JobRunning"),
                Some("the run's Job is still active"),
                "2026-08-26T11:00:00+02:00",
            ),
        );

        assert_eq!(
            sole(&conditions).last_transition_time,
            at("2026-08-26T10:00:00+02:00")
        );
    }

    #[test]
    fn a_condition_of_another_type_is_appended_beside_it() {
        let mut conditions = vec![ready(
            "True",
            Some("JobRunning"),
            None,
            "2026-08-26T10:00:00+02:00",
        )];

        upsert_condition(
            &mut conditions,
            TestCondition {
                type_: "Blocked",
                status: "True",
                reason: Some("HostLockHeld"),
                message: None,
                last_transition_time: at("2026-08-26T11:00:00+02:00"),
            },
        );

        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[1].type_, "Blocked");
    }
}
