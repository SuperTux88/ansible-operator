from __future__ import annotations

import base64
import json
import zlib

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
    ...} — a fixed-order array per host, no spaces. The last element is 1 when the host reached the
    operator''s completion marker.'
  - The kubelet caps that message at 4096 bytes, so a fleet large enough to exceed it is written
    deflated and base64-encoded behind a `z:` prefix instead. See TERMINATION_MESSAGE_MAX_BYTES.
requirements:
  - Enabled via ANSIBLE_CALLBACKS_ENABLED (this callback sets CALLBACK_NEEDS_ENABLED).
"""

# Default terminationMessagePath; the kubelet surfaces this file's contents as the container's
# state.terminated.message once it exits.
TERMINATION_LOG_PATH = "/dev/termination-log"

# The kubelet's MaxContainerTerminationMessageLength. It truncates to this and keeps the *leading*
# bytes, so an oversized recap does not arrive partial — it arrives as invalid JSON, and the operator
# can only report every host `Unknown` and spend the run's whole attempt budget re-producing it.
# Plain JSON runs out at roughly 60 hosts with cloud-provider node names, which is why the fallback
# below exists rather than a warning about it.
TERMINATION_MESSAGE_MAX_BYTES = 4096

# Marks a recap written deflated + base64 rather than as plain JSON. Kept out of the JSON itself so
# the reader can tell the two apart before parsing either. Must stay in lockstep with
# `callback_output::parse_callback_output`.
COMPRESSED_PREFIX = "z:"

# Marks a recap that would not fit even compressed, followed by the host count. Compression moves the
# ceiling into the hundreds of hosts but does not remove it, and the operator cannot tell a recap
# that overflowed from one a crash never wrote — both are simply unparseable. Writing a marker that
# *does* fit is what turns the remaining ceiling from silence into a diagnostic naming it.
OVERSIZE_PREFIX = "!:"

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
        for host in stats.processed:
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
                f.write(encode_recap(recap))
        except OSError:
            # Best-effort: if the file can't be written, the operator sees an empty termination
            # message and treats every host as Unknown (same as a hard crash before this hook).
            pass


def encode_recap(recap):
    """Renders the recap for the termination message, compressing only if it would not fit.

    Staying with plain JSON while it fits is deliberate: it keeps the message readable with a bare
    `kubectl get pod -o jsonpath=...` for every cluster small enough that someone would try, and it
    keeps the compressed path off the hot path for the common case. Above the cap, the recap is
    highly redundant — repeated node-name prefixes and long runs of zero counters — so deflate buys
    roughly 3-5x, which moves the ceiling from ~60 hosts into the hundreds.

    Past even that, a marker naming the host count is written instead. It costs the same per-host
    detail an unwritable message costs, but it is the difference between the operator reporting
    "the recap could not be read" and reporting why — and the operator cannot work it out for
    itself, since an overflowed message and a crashed one are equally unparseable.
    """
    payload = json.dumps(recap, separators=(",", ":"))
    if len(payload.encode("utf-8")) <= TERMINATION_MESSAGE_MAX_BYTES:
        return payload

    compressed = zlib.compress(payload.encode("utf-8"), 9)
    compressed = COMPRESSED_PREFIX + base64.b64encode(compressed).decode("ascii")
    if len(compressed.encode("utf-8")) <= TERMINATION_MESSAGE_MAX_BYTES:
        return compressed

    return f"{OVERSIZE_PREFIX}{len(recap)}"
