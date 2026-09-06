"""Tests for the recap callback (`src/v1beta1/ansible/ansible_operator_recap.py`).

The callback ships as a file inside the workspace Secret rather than as an importable package, so it
is loaded from its path here — the same file the operator embeds, not a copy. `ansible` itself is
stubbed rather than installed: the plugin uses `CallbackBase` only as a base class, and the point of
these tests is the arithmetic the operator depends on, not ansible's dispatch.

What is being pinned is the one thing ansible's own counters cannot express. A host the playbook
stopped short of — `any_errors_fatal`, a failed `serial` batch, a `max_fail_percentage` abort —
reports `failed=0, unreachable=0`, identical to a host that ran every task. The completion marker is
what separates them, so a bug here does not look like a bug: it looks like a converged fleet.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
import types
import unittest
import zlib
from pathlib import Path
from unittest import mock

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "v1beta1"
    / "ansible"
    / "ansible_operator_recap.py"
)


def load_recap():
    """Loads the callback with a stand-in for the one ansible symbol it imports."""
    callback_module = types.ModuleType("ansible.plugins.callback")

    class CallbackBase:
        def __init__(self, *args, **kwargs):
            pass

    callback_module.CallbackBase = CallbackBase
    ansible = types.ModuleType("ansible")
    plugins = types.ModuleType("ansible.plugins")

    with mock.patch.dict(
        sys.modules,
        {
            "ansible": ansible,
            "ansible.plugins": plugins,
            "ansible.plugins.callback": callback_module,
        },
    ):
        spec = importlib.util.spec_from_file_location("ansible_operator_recap", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


recap = load_recap()

OK, CHANGED, UNREACHABLE, FAILED, SKIPPED, RESCUED, IGNORED, COMPLETED = range(8)


class FakeStats:
    def __init__(self, hosts):
        self.processed = {host: True for host in hosts}
        self._summaries = hosts

    def summarize(self, host):
        return self._summaries[host]


def summary(ok=0, changed=0, unreachable=0, failures=0, skipped=0, rescued=0, ignored=0):
    return {
        "ok": ok,
        "changed": changed,
        "unreachable": unreachable,
        "failures": failures,
        "skipped": skipped,
        "rescued": rescued,
        "ignored": ignored,
    }


def result_for(host, task):
    return types.SimpleNamespace(
        _host=types.SimpleNamespace(get_name=lambda: host),
        _task=types.SimpleNamespace(get_name=lambda: task),
    )


def decode(message):
    """The reader's half of the wire format — mirrors `callback_output::parse_callback_output`."""
    if message.startswith(recap.COMPRESSED_PREFIX):
        payload = zlib.decompress(
            base64.b64decode(message[len(recap.COMPRESSED_PREFIX) :])
        ).decode("utf-8")
    else:
        payload = message
    return json.loads(payload)


def write(marker_hosts, summaries):
    """Drives one playbook's worth of callbacks and returns the raw termination message."""
    callback = recap.CallbackModule()
    for host in marker_hosts:
        callback.v2_runner_on_ok(result_for(host, recap.COMPLETION_MARKER_TASK))
    with tempfile.NamedTemporaryFile("r+") as log:
        with mock.patch.object(recap, "TERMINATION_LOG_PATH", log.name):
            callback.v2_playbook_on_stats(FakeStats(summaries))
        log.seek(0)
        return log.read()


def run(marker_hosts, summaries):
    """Drives one playbook's worth of callbacks and returns the parsed termination message."""
    return decode(write(marker_hosts, summaries))


class RecapTest(unittest.TestCase):
    def test_a_host_that_reached_the_marker_is_reported_complete(self):
        written = run(["node-a"], {"node-a": summary(ok=4, changed=2)})

        self.assertEqual(written["node-a"][COMPLETED], 1)

    def test_the_markers_own_ok_is_not_counted_against_the_playbook(self):
        """The marker is the operator's task. A user reading the recap must see their playbook's
        numbers, and the operator's own arithmetic must not drift from what stdout showed them by
        more than the one task it added."""
        written = run(["node-a"], {"node-a": summary(ok=4, changed=2)})

        self.assertEqual(written["node-a"][OK], 3)
        self.assertEqual(written["node-a"][CHANGED], 2)

    def test_a_host_the_play_stopped_short_of_is_not_complete(self):
        """The defect this exists for: `cut-short` and `finished` are identical on every counter
        ansible has, and only one of them received the whole playbook."""
        written = run(
            ["finished"],
            {
                "cut-short": summary(ok=1, skipped=1),
                "finished": summary(ok=2, skipped=1),
            },
        )

        self.assertEqual(written["cut-short"][:IGNORED + 1], written["finished"][:IGNORED + 1])
        self.assertEqual(written["cut-short"][COMPLETED], 0)
        self.assertEqual(written["finished"][COMPLETED], 1)

    def test_a_failed_host_is_reported_with_its_counters_and_no_completion(self):
        written = run([], {"bad-c": summary(ok=1, failures=1)})

        self.assertEqual(written["bad-c"][FAILED], 1)
        self.assertEqual(written["bad-c"][COMPLETED], 0)
        self.assertEqual(written["bad-c"][OK], 1, "nothing is subtracted from a host with no marker")

    def test_a_host_no_play_targeted_reports_completion_with_no_counters(self):
        """It reaches the marker (which targets `all`) and nothing else. Empty counters plus
        completion is the honest description: applying this playbook to it was vacuous."""
        written = run(["db-1"], {"db-1": summary(ok=1)})

        self.assertEqual(written["db-1"], [0, 0, 0, 0, 0, 0, 0, 1])

    def test_every_host_is_reported_as_eight_fixed_order_fields(self):
        """The reader parses positionally and rejects any other length, so a shape change here is a
        run-wide `Unknown` rather than a silent misread — but only if the length actually moves."""
        written = run(["node-a"], {"node-a": summary(ok=2, rescued=1, ignored=3)})

        self.assertEqual(len(written["node-a"]), 8)
        self.assertEqual(written["node-a"][RESCUED], 1)
        self.assertEqual(written["node-a"][IGNORED], 3)

    def test_a_marker_result_for_an_unprocessed_host_is_ignored(self):
        written = run(["ghost"], {"node-a": summary(ok=1)})

        self.assertNotIn("ghost", written)

    def test_an_unwritable_termination_log_is_not_fatal(self):
        callback = recap.CallbackModule()
        with mock.patch.object(recap, "TERMINATION_LOG_PATH", "/nonexistent/dir/log"):
            callback.v2_playbook_on_stats(FakeStats({"node-a": summary(ok=1)}))


class EncodingTest(unittest.TestCase):
    """The kubelet caps the termination message at 4096 bytes and keeps the *leading* portion, so a
    recap that does not fit does not arrive partial — it arrives as invalid JSON, and the operator
    reads every host `Unknown` on every retry until the attempt budget is gone. These pin the escape
    from that, and the fact that small fleets do not pay for it."""

    CAP = recap.TERMINATION_MESSAGE_MAX_BYTES

    @staticmethod
    def fleet(count):
        return {
            f"ip-10-0-{i // 250}-{i % 250}.eu-central-1.compute.internal": summary(
                ok=12, changed=3, skipped=7
            )
            for i in range(count)
        }

    def test_a_recap_that_fits_is_written_as_plain_readable_json(self):
        message = write([], self.fleet(10))

        self.assertFalse(message.startswith(recap.COMPRESSED_PREFIX))
        self.assertEqual(json.loads(message), decode(message))

    def test_a_recap_that_would_not_fit_is_compressed_and_does_fit(self):
        hosts = self.fleet(200)
        plain = json.dumps({h: [0] * 8 for h in hosts}, separators=(",", ":"))
        self.assertGreater(len(plain), self.CAP, "the plain form must exceed the cap")

        message = write([], hosts)

        self.assertTrue(message.startswith(recap.COMPRESSED_PREFIX))
        self.assertLessEqual(len(message.encode("utf-8")), self.CAP)

    def test_compression_preserves_every_host_and_counter(self):
        hosts = self.fleet(200)
        hosts["ip-10-0-0-0.eu-central-1.compute.internal"] = summary(failures=1)

        written = run(["ip-10-0-0-1.eu-central-1.compute.internal"], hosts)

        self.assertEqual(len(written), 200)
        self.assertEqual(written["ip-10-0-0-0.eu-central-1.compute.internal"][FAILED], 1)
        self.assertEqual(written["ip-10-0-0-1.eu-central-1.compute.internal"][COMPLETED], 1)
        self.assertEqual(
            written["ip-10-0-0-2.eu-central-1.compute.internal"],
            [12, 3, 0, 0, 7, 0, 0, 0],
        )

    def test_a_fleet_past_even_the_compressed_ceiling_writes_a_marker_that_fits(self):
        """Compression moves the ceiling into the hundreds of hosts; it does not remove it. Past it
        the operator would otherwise see the same unparseable message a crashed container leaves,
        and report the plan `Unknown` with no way to learn why."""
        hosts = self.fleet(20000)

        message = write([], hosts)

        self.assertTrue(message.startswith(recap.OVERSIZE_PREFIX))
        self.assertLessEqual(len(message.encode("utf-8")), self.CAP)
        self.assertEqual(
            int(message[len(recap.OVERSIZE_PREFIX) :]),
            20000,
            "the host count is the whole payload; without it the marker says nothing a crash does not",
        )

    def test_a_fleet_that_still_compresses_is_never_reduced_to_a_marker(self):
        """The marker discards every per-host result, so it must be the last resort and not merely
        the response to exceeding the plain-JSON cap."""
        message = write([], self.fleet(200))

        self.assertFalse(message.startswith(recap.OVERSIZE_PREFIX))

    def test_the_boundary_is_measured_in_bytes_not_characters(self):
        """A non-ASCII inventory hostname costs more bytes than characters, and it is bytes the
        kubelet counts."""
        hosts = {f"höst-{i}-ünicode-name-padding" * 3: summary(ok=1) for i in range(60)}

        message = write([], hosts)

        self.assertLessEqual(len(message.encode("utf-8")), self.CAP)
        self.assertEqual(len(run([], hosts)), 60)


if __name__ == "__main__":
    unittest.main()
