"""Tests for the managed-ssh preflight gate (`src/v1beta1/ansible/ansible_operator_preflight.py`).

The gate ships as a script inside the workspace Secret rather than as an importable package, so it
is loaded from its path here — the same file the operator embeds, not a copy.

Everything is exercised against a real socket. What the gate is *for* is the difference between what
a peer does on the wire and what the operator can infer about it, and a fake that hands the parser
tidy byte strings would answer questions the parser was never the risky part of. No sshd is
involved: the gate only reads until a peer identifies itself, and a listener that writes bytes is a
complete stand-in for that.
"""

from __future__ import annotations

import importlib.util
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "v1beta1"
    / "ansible"
    / "ansible_operator_preflight.py"
)


def load_preflight():
    spec = importlib.util.spec_from_file_location("ansible_operator_preflight", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load_preflight()

BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


class Listener:
    """A one-connection TCP server that runs `script(connection, stop)` on whatever connects.

    The script is expected to lose its connection at any point: the gate closes as soon as it has
    its answer, so a server still writing sees `BrokenPipeError`/`ConnectionResetError`. That is the
    behaviour under test, not a failure, so it is swallowed here — and swallowed *only* here, where
    the writes happen.

    `stop` is set by `close`, so a script that models a peer saying nothing waits on it instead of
    sleeping: the test only needs the silence to outlast the gate's deadline, and a fixed sleep
    would make it outlast the test run too.
    """

    def __init__(self, script):
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        # Closing a socket does not reliably wake a thread blocked in `accept`, so the wait is
        # polled instead: a test whose peer is never dialled must not hold its cleanup for seconds.
        self._socket.settimeout(0.05)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, args=(script,), daemon=True)
        self._thread.start()

    def _serve(self, script):
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            # Before OSError, which it subclasses: this one is the poll expiring, not the socket
            # going away.
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                try:
                    script(connection, self._stop)
                except OSError:
                    pass
            return

    def close(self):
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=5)


def silent(connection, stop):
    """A peer that accepts the connection and then says nothing at all."""
    stop.wait(30)


class ReachableTest(unittest.TestCase):
    def assert_reachable(self, script, expected, budget=3.0):
        listener = Listener(script)
        self.addCleanup(listener.close)
        started = time.monotonic()
        answered = preflight.reachable("127.0.0.1", listener.port, time.monotonic() + budget)
        self.assertEqual(answered, expected)
        return time.monotonic() - started

    def test_a_whole_banner_in_one_write_is_reachable(self):
        self.assert_reachable(lambda connection, stop: connection.sendall(BANNER), True)

    def test_a_banner_split_across_segments_is_reachable(self):
        """The case the single `recv` got wrong: `SSH-` may not arrive in one piece."""

        def dribble(connection, stop):
            for byte in BANNER:
                connection.sendall(bytes([byte]))
                time.sleep(0.005)

        self.assert_reachable(dribble, True)

    def test_the_identification_line_is_accepted_without_its_newline(self):
        """Four bytes are the whole question; the gate must not wait out the rest of the line."""
        self.assert_reachable(lambda connection, stop: connection.sendall(b"SSH-"), True)

    def test_lines_before_the_identification_line_are_skipped(self):
        """RFC 4253 lets a server send these first. The proxies here do not, but the rule is
        cheaper to honour than to special-case."""

        def chatty(connection, stop):
            connection.sendall(b"this space intentionally left blank\r\n")
            time.sleep(0.01)
            connection.sendall(BANNER)

        self.assert_reachable(chatty, True)

    def test_a_peer_that_accepts_and_closes_is_unreachable(self):
        """A proxy mid-restart. EOF has to be a definite answer, or the read loop spins on a closed
        socket until the deadline."""
        elapsed = self.assert_reachable(lambda connection, stop: None, False)
        self.assertLess(elapsed, 1.0, "EOF must be answered at once, not waited out")

    def test_a_peer_speaking_another_protocol_is_unreachable(self):
        self.assert_reachable(
            lambda connection, stop: connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
            False,
        )

    def test_a_peer_sending_too_many_lines_is_unreachable(self):
        def noisy(connection, stop):
            for number in range(preflight.MAX_BANNER_LINES + 1):
                connection.sendall(b"line %d\r\n" % number)
            connection.sendall(BANNER)

        elapsed = self.assert_reachable(noisy, False)
        self.assertLess(elapsed, 1.0, "the line cap must answer, not wait for the deadline")

    def test_a_peer_sending_endless_bytes_is_unreachable(self):
        """No newline and no `SSH-`, so only the byte cap ends this."""

        def flood(connection, stop):
            while not stop.is_set():
                connection.sendall(b"x" * 512)

        elapsed = self.assert_reachable(flood, False)
        self.assertLess(elapsed, 1.0, "the byte cap must answer, not wait for the deadline")

    def test_a_silent_peer_is_unreachable_once_the_deadline_passes(self):
        elapsed = self.assert_reachable(silent, False, budget=0.5)
        self.assertGreaterEqual(elapsed, 0.4, "a silent peer is given its share of the budget")
        self.assertLess(elapsed, 3.0, "and no more than the deadline allows")

    def test_a_spent_deadline_dials_nothing(self):
        listener = Listener(lambda connection, stop: connection.sendall(BANNER))
        self.addCleanup(listener.close)

        self.assertFalse(
            preflight.reachable("127.0.0.1", listener.port, time.monotonic() - 1),
            "a dial starting past the deadline cannot extend it",
        )

    def test_a_refused_connection_is_unreachable(self):
        listener = Listener(lambda connection, stop: None)
        port = listener.port
        listener.close()

        self.assertFalse(preflight.reachable("127.0.0.1", port, time.monotonic() + 1))


class WaitForTest(unittest.TestCase):
    def test_every_reachable_endpoint_is_reported_and_none_are_left_pending(self):
        listeners = [
            Listener(lambda connection, stop: connection.sendall(BANNER)) for _ in range(4)
        ]
        for listener in listeners:
            self.addCleanup(listener.close)
        endpoints = [(f"node-{i}", "127.0.0.1", l.port) for i, l in enumerate(listeners)]

        pending, elapsed = preflight.wait_for(endpoints, 5.0)

        self.assertEqual(pending, [])
        self.assertLess(elapsed, 2.0)

    def test_the_deadline_bounds_the_whole_wait_however_many_endpoints_there_are(self):
        """More endpoints than workers, so the sweep is several batches — the case a per-sweep
        budget would have granted a fresh dial timeout to each of."""
        listener = Listener(silent)
        self.addCleanup(listener.close)
        endpoints = [
            (f"node-{i}", "127.0.0.1", listener.port)
            for i in range(preflight.MAX_CONCURRENT_DIALS * 2)
        ]

        pending, elapsed = preflight.wait_for(endpoints, 1.0)

        self.assertEqual(len(pending), len(endpoints))
        self.assertLess(elapsed, 3.0, "batches must share one deadline, not each get their own")

    def test_refused_connection_retries_are_bounded_by_the_poll_interval(self):
        listener = Listener(lambda connection, stop: None)
        port = listener.port
        listener.close()
        calls = []
        original_reachable = preflight.reachable

        def counted_reachable(*args):
            calls.append(args)
            return original_reachable(*args)

        endpoint = [("node", "127.0.0.1", port)]
        with mock.patch.object(preflight, "reachable", side_effect=counted_reachable):
            pending, _ = preflight.wait_for(endpoint, 1.0)

        self.assertEqual(pending, endpoint)
        self.assertLessEqual(
            len(calls), int(1.0 / preflight.POLL_INTERVAL_SECONDS) + 1,
            "a refused connection must not make the polling loop free-run",
        )


class ReadEndpointsTest(unittest.TestCase):
    def write(self, contents):
        import tempfile

        handle = tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        with handle:
            handle.write(contents)
        return handle.name

    def test_well_formed_lines_are_parsed_and_the_rest_are_skipped(self):
        path = self.write(
            "node-a\t10.42.1.7\t22\n"
            "\n"
            "not-an-endpoint\n"
            "node-b\t10.42.3.9\t2222\n"
            "too\tmany\tfields\there\n"
        )

        self.assertEqual(
            preflight.read_endpoints(path),
            [("node-a", "10.42.1.7", 22), ("node-b", "10.42.3.9", 2222)],
        )

    def test_an_empty_file_yields_nothing_to_wait_for(self):
        self.assertEqual(preflight.read_endpoints(self.write("")), [])

    def test_a_malformed_port_is_reported_without_discarding_other_endpoints(self):
        path = self.write(
            "node-a\t10.42.1.7\t22\n"
            "node-b\t10.42.2.8\tnot-a-port\n"
            "node-c\t10.42.3.9\t2222\n"
        )

        with mock.patch.object(preflight, "log") as log:
            endpoints = preflight.read_endpoints(path)

        self.assertEqual(
            endpoints,
            [("node-a", "10.42.1.7", 22), ("node-c", "10.42.3.9", 2222)],
        )
        log.assert_called_once_with(
            "ignoring malformed endpoint on line 2: "
            "'node-b\\t10.42.2.8\\tnot-a-port'"
        )


if __name__ == "__main__":
    unittest.main()
