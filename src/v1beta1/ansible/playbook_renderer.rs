use serde_yaml::{Mapping, Sequence, Value};

use crate::v1beta1;

/// Name of the task whose per-host results tell the operator which hosts reached the end of the
/// playbook.
///
/// Ansible's recap cannot express the difference between "ran the whole playbook" and "was fine up
/// to the point the play stopped": under `any_errors_fatal`, a `serial` batch failure or a
/// `max_fail_percentage` abort, a host that never ran the remaining tasks still reports
/// `failed=0, unreachable=0` and is indistinguishable from one that completed. No callback hook
/// announces the abort either — the run goes straight from the last task to `v2_playbook_on_stats`.
///
/// So the operator asks a question Ansible will answer: it appends a play that runs one trivial task,
/// and a host that produces a result for it is one the playbook did not stop short of. An abort ends
/// the whole playbook run, so the marker play never runs at all; a host that merely failed or went
/// unreachable is dropped from every later play, so it does not reach the marker either — which
/// makes the answer per host rather than per run.
///
/// **Must stay in lockstep with `ansible_operator_recap.py`,** which matches results by this exact
/// name to record completion and to keep the marker out of the counters it reports.
/// `the_marker_task_name_matches_the_callback_that_reads_it` fails if the two drift apart.
pub const COMPLETION_MARKER_TASK: &str = "__ansible_operator_play_completed";

const COMPLETION_MARKER_PLAY: &str = "__ansible_operator_completion_marker";

pub fn render_playbook(spec: &v1beta1::PlaybookPlanSpec) -> Result<String, super::RenderError> {
    let mut plays: Sequence = serde_yaml::from_str(&spec.template.playbook)?;
    plays.push(completion_marker_play());
    Ok(serde_yaml::to_string(&plays)?)
}

/// The appended play, targeting `all` so it reports on every host the run still has.
///
/// `debug` runs on the controller, so the marker costs no connection to a host that has just been
/// through a playbook — and a host whose connection did break is already out of the run by the time
/// this play starts. `gather_facts: false` keeps it from being the one thing in the run that dials
/// every host again.
///
/// **The marker task carries no tags, and adding `tags: [always]` is not the free fix it looks
/// like.** `render_ansible_command` passes neither `--tags` nor `--skip-tags`, so nothing filters
/// tasks today and this is inert either way — measured, the callback's output is byte-identical with
/// and without the tag. If tag support is ever added, though, both spellings are wrong, in opposite
/// directions:
///
/// - untagged, `--tags <anything>` drops the marker, so every host of every plan reports
///   `Incomplete` and nothing is ever stamped converged again;
/// - with `tags: [always]`, the marker survives `--tags config` and the hosts read `Succeeded` — so
///   `status::apply_terminal_play_status` stamps `lastAppliedHash` for the *whole* playbook on a host
///   that only ran the `config` tasks. That is precisely the defect the marker was introduced to
///   stop: a partially applied host recorded as converged, permanently, and silently.
///
/// So the tag is not the decision to make first. Fold the tag selection into the execution hash, so
/// that a `--tags config` run has a hash of its own and stamping it claims only what it applied;
/// once that holds, `tags: [always]` here becomes correct and necessary. Until then the untagged
/// marker is the safer of two wrong answers, because it fails loudly and never claims convergence
/// it does not have. (Note `--skip-tags always` would defeat the tag anyway, so it was never
/// absolute protection.)
fn completion_marker_play() -> Value {
    let mut task = Mapping::new();
    task.insert(
        Value::String("name".into()),
        Value::String(COMPLETION_MARKER_TASK.into()),
    );
    let mut debug_args = Mapping::new();
    debug_args.insert(
        Value::String("msg".into()),
        Value::String("ansible-operator completion marker".into()),
    );
    task.insert(
        Value::String("ansible.builtin.debug".into()),
        Value::Mapping(debug_args),
    );

    let mut play = Mapping::new();
    play.insert(
        Value::String("name".into()),
        Value::String(COMPLETION_MARKER_PLAY.into()),
    );
    play.insert(Value::String("hosts".into()), Value::String("all".into()));
    play.insert(Value::String("gather_facts".into()), Value::Bool(false));
    play.insert(
        Value::String("tasks".into()),
        Value::Sequence(vec![Value::Mapping(task)]),
    );

    Value::Mapping(play)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(playbook: &str) -> v1beta1::PlaybookPlanSpec {
        let mut spec = v1beta1::PlaybookPlanSpec {
            image: "example/ansible:1".into(),
            ..Default::default()
        };
        spec.template.playbook = playbook.into();
        spec
    }

    #[test]
    fn the_marker_play_is_appended_after_every_play_the_author_wrote() {
        let rendered = render_playbook(&spec(
            "- hosts: webservers\n  tasks: []\n- hosts: dbservers\n  tasks: []\n",
        ))
        .unwrap();
        let plays: Sequence = serde_yaml::from_str(&rendered).unwrap();

        assert_eq!(plays.len(), 3);
        assert_eq!(plays[0]["hosts"], Value::String("webservers".into()));
        assert_eq!(plays[1]["hosts"], Value::String("dbservers".into()));
        // Last, so nothing the author wrote runs after it: reaching it has to mean the playbook is
        // done with that host.
        assert_eq!(plays[2]["hosts"], Value::String("all".into()));
        assert_eq!(
            plays[2]["tasks"][0]["name"],
            Value::String(COMPLETION_MARKER_TASK.into())
        );
    }

    /// The marker exists to be recognised by the callback, and nothing but a test keeps the two
    /// spellings together: a rename on either side would leave every host looking like the playbook
    /// stopped short of it, which reads as "nothing converged" on every plan at once.
    #[test]
    fn the_marker_task_name_matches_the_callback_that_reads_it() {
        let callback = include_str!("./ansible_operator_recap.py");

        assert!(
            callback.contains(&format!("\"{COMPLETION_MARKER_TASK}\"")),
            "the callback must match the marker task by the name the renderer emits"
        );
    }

    /// The author's own plays are passed through untouched — the marker is an addition, never a
    /// rewrite of what they wrote.
    #[test]
    fn the_authors_plays_are_rendered_unchanged() {
        let playbook = "- hosts: all\n  any_errors_fatal: true\n  serial: 2\n  tasks:\n    - ansible.builtin.ping:\n";
        let rendered = render_playbook(&spec(playbook)).unwrap();
        let plays: Sequence = serde_yaml::from_str(&rendered).unwrap();
        let original: Sequence = serde_yaml::from_str(playbook).unwrap();

        assert_eq!(plays[0], original[0]);
    }
}
