from __future__ import annotations

import json

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
callback: ansible_operator_recap
type: notification
short_description: Emits a machine-readable per-host outcome summary for ansible-operator.
description:
  - Hooks the same playbook-stats event the default callback uses, without replacing it, so
    human-readable stdout (the PLAY RECAP) is unaffected.
  - At end of run, writes a compact JSON map to the container's termination-message file
    (/dev/termination-log). ansible-operator reads it back from the finished container's
    terminated state instead of scraping logs, since one Job can span many hosts and its own
    exit code no longer maps to any single host's result.
  - 'Format: {"<host>": [ok, changed, unreachable, failed, skipped, rescued, ignored, completed],
    ...} — a fixed-order array per host, no spaces, to stay well under the kubelet''s message size
    cap. The last element is 1 when the host reached the operator''s completion marker.'
requirements:
  - Enabled via ANSIBLE_CALLBACKS_ENABLED (this callback sets CALLBACK_NEEDS_ENABLED).
"""

# Default terminationMessagePath; the kubelet surfaces this file's contents as the container's
# state.terminated.message once it exits.
TERMINATION_LOG_PATH = "/dev/termination-log"

# The task the operator appends to every playbook, in a play of its own, to learn which hosts the
# playbook did not stop short of. Ansible's counters cannot say: a host that never ran the rest of
# an aborted play reports failed=0/unreachable=0, exactly like one that ran everything, and no
# callback hook announces the abort.
#
# Must stay in lockstep with COMPLETION_MARKER_TASK in playbook_renderer.rs, which emits this name.
COMPLETION_MARKER_TASK = "__ansible_operator_play_completed"


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "ansible_operator_recap"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._completed = set()

    def v2_runner_on_ok(self, result):
        if result._task.get_name() == COMPLETION_MARKER_TASK:
            self._completed.add(result._host.get_name())

    def v2_playbook_on_stats(self, stats):
        # Fixed wire order — must stay in lockstep with HostStats::from([u32; 8]) on the reader.
        recap = {}
        for host in stats.processed.keys():
            s = stats.summarize(host)
            completed = host in self._completed
            recap[host] = [
                # The marker is the operator's own task, so its `ok` is taken back out: the counters
                # a user reads have to be the ones their playbook produced.
                max(s.get("ok", 0) - (1 if completed else 0), 0),
                s.get("changed", 0),
                s.get("unreachable", 0),
                s.get("failures", 0),
                s.get("skipped", 0),
                s.get("rescued", 0),
                s.get("ignored", 0),
                1 if completed else 0,
            ]

        try:
            with open(TERMINATION_LOG_PATH, "w") as f:
                f.write(json.dumps(recap, separators=(",", ":")))
        except OSError:
            # Best-effort: if the file can't be written, the operator sees an empty termination
            # message and treats every host as Unknown (same as a hard crash before this hook).
            pass
