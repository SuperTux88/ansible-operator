"""Managed-ssh preflight gate: waits until every proxy endpoint of this run answers with an SSH
banner, then lets the Ansible container start.

Runs as the Job pod's last init container, which is the only vantage point that proves anything:
the proxy pods' ingress NetworkPolicy selects the Job pod by label, so the CNI can only begin
programming that rule on the proxies' nodes once the Job pod exists. Until it has, a remote proxy
refuses or drops the connection even though kubelet reports the pod Ready — kubelet probes from the
node, not from this network namespace.

Never fails the run once it is running. On timeout the still-unreachable hosts are left to Ansible,
which records them `unreachable` exactly as it would have without this gate; the run is retried
later. An unexpected error here is reported on stderr and otherwise ignored, because a broken
preflight must not be able to wedge a Job that would have worked. What this cannot cover is failing
to start at all — an image with no `python3` on `PATH` never reaches this code, which is why the
image contract requires one.

Invoked as `<interpreter> <this file> <endpoints file>`. The endpoints file is rendered into the
workspace Secret by the operator (see `workspace.rs`) and holds one `host<TAB>ip<TAB>port` line per
proxy this run can actually reach; hosts whose proxy never came up are deliberately absent.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from concurrent import futures

# Overridden by the operator via the init container's env (see `job_builder.rs`); the default only
# applies if the script is run by hand.
TIMEOUT_ENV = "ANSIBLE_OPERATOR_PREFLIGHT_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT_SECONDS = 60.0

POLL_INTERVAL_SECONDS = 0.5

# Bounds a single dial so one endpoint that black-holes packets (rather than refusing them) cannot
# eat the whole budget. It bounds the connect and the banner read separately, and both are clamped
# to whatever is left of the overall deadline, so no dial can outlive the gate it belongs to.
CONNECT_TIMEOUT_SECONDS = 2.0

# How many endpoints are dialled at once. A run has one proxy per targeted Node and nothing bounds
# how many Nodes a `ClusterInventory` matches, so without a cap the pool sizes itself to the fleet:
# one thread and one socket per Node, and on a large enough cluster the interpreter fails to start
# the threads at all — which the fail-open handler turns into "no gate today".
#
# Small is enough because the dials this exists for are cheap: a proxy whose datapath is not
# programmed yet refuses the connection in microseconds, so a sweep of hundreds of endpoints costs
# little more with 32 workers than with hundreds. Only endpoints that black-hole packets hold a
# worker for the full `CONNECT_TIMEOUT_SECONDS`, and the deadline is what bounds those.
MAX_CONCURRENT_DIALS = 32

# sshd sends its identification string as soon as the connection is accepted. Requiring it rules out
# a half-programmed datapath where the SYN is answered but sshd is not actually serving us yet.
BANNER_PREFIX = b"SSH-"

# Bytes per read. The identification string is far shorter, so this is one read in practice.
BANNER_BYTES = 256

# Bounds on what a peer can make this spend before it is judged unreachable. Both are generous
# against the ~21 bytes and single line an OpenSSH proxy actually sends, and neither is a diagnosis:
# a peer that talks past them is answered `False`, the same as one that says nothing at all.
#
# RFC 4253 lets a server send other lines before its identification string, which the proxies this
# dials never do — the allowance costs one counter and spares the alternative rule, "the first chunk
# must start with SSH-, except when TCP splits it".
MAX_BANNER_BYTES = 4096
MAX_BANNER_LINES = 8


def log(message):
    print(f"preflight: {message}", file=sys.stderr, flush=True)


def read_endpoints(path):
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()

    endpoints = []
    for number, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            log(f"ignoring malformed endpoint on line {number}: {line!r}")
            continue
        host, address, port = fields
        try:
            port = int(port)
        except ValueError:
            log(f"ignoring malformed endpoint on line {number}: {line!r}")
            continue
        endpoints.append((host, address, port))

    return endpoints


def dial_timeout(deadline):
    """Seconds a single connect or read may take, or `None` once the gate is out of time.

    Taken from the absolute deadline rather than from a budget computed per sweep, because the
    worker cap means a sweep is several batches and a per-sweep budget would grant each of them a
    fresh `CONNECT_TIMEOUT_SECONDS` — turning the 60 seconds the gate advertises into 60 seconds per
    batch. Applied to the connect and the banner read separately for the same reason: a dial that
    spends the constant on each phase costs twice what the constant says.
    """
    remaining = deadline - time.monotonic()
    return min(CONNECT_TIMEOUT_SECONDS, remaining) if remaining > 0 else None


def reachable(address, port, deadline):
    connect_timeout = dial_timeout(deadline)
    if connect_timeout is None:
        return False

    try:
        with socket.create_connection((address, port), timeout=connect_timeout) as sock:
            return read_banner(sock, deadline)
    except OSError:
        return False


def read_banner(sock, deadline):
    """Whether the peer identifies itself as an SSH server before the deadline.

    Reads rather than peeks at a single chunk, because one `recv` is not the same question: TCP may
    hand back part of the identification string, and judging a proxy unreachable over a segment
    boundary means retrying it every poll interval — or, if the split is deterministic, spending the
    gate's whole budget on a proxy that was serving all along.

    A partial first line is accepted as soon as it starts with `SSH-`, without waiting for the
    newline that would complete it: those four bytes are the whole question, and the rest of the
    string says nothing this gate acts on. Complete lines that are *not* the identification string
    are skipped, which is what RFC 4253 permits a server to send first.

    Every way this can end is `False` rather than an exception: the deadline passing, EOF from a peer
    that accepted and closed (a proxy mid-restart does exactly that, and it must be a definite answer
    or the loop spins against a closed socket), or a peer that exceeds either cap. The caller treats
    them alike — the host is dialled again on the next sweep.
    """
    line = b""
    read = 0
    skipped = 0

    while True:
        timeout = dial_timeout(deadline)
        if timeout is None:
            return False

        sock.settimeout(timeout)
        chunk = sock.recv(BANNER_BYTES)
        if not chunk:
            return False

        read += len(chunk)
        line += chunk
        while b"\n" in line:
            complete, line = line.split(b"\n", 1)
            if complete.startswith(BANNER_PREFIX):
                return True
            skipped += 1
            if skipped >= MAX_BANNER_LINES:
                return False

        if line.startswith(BANNER_PREFIX):
            return True
        if read >= MAX_BANNER_BYTES:
            return False


def wait_for(endpoints, timeout):
    started = time.monotonic()
    deadline = started + timeout
    pending = list(endpoints)

    workers = min(len(endpoints), MAX_CONCURRENT_DIALS)
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        while pending:
            if time.monotonic() >= deadline:
                break

            results = pool.map(
                lambda endpoint: reachable(endpoint[1], endpoint[2], deadline), pending
            )

            still_pending = []
            for endpoint, answered in zip(pending, results):
                if answered:
                    host, address, port = endpoint
                    elapsed = time.monotonic() - started
                    log(f"{host} ({address}:{port}) reachable after {elapsed:.1f}s")
                else:
                    still_pending.append(endpoint)
            pending = still_pending

            if pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(POLL_INTERVAL_SECONDS, remaining))

    return pending, time.monotonic() - started


def main(argv):
    if len(argv) != 2:
        log(f"expected exactly one argument (the endpoints file), got {len(argv) - 1}")
        return

    endpoints = read_endpoints(argv[1])
    if not endpoints:
        log("no reachable managed-ssh proxies to wait for")
        return

    timeout = float(os.environ.get(TIMEOUT_ENV) or DEFAULT_TIMEOUT_SECONDS)
    unreachable, elapsed = wait_for(endpoints, timeout)

    if unreachable:
        names = ", ".join(f"{host} ({address}:{port})" for host, address, port in unreachable)
        log(
            f"giving up after {elapsed:.1f}s with {len(unreachable)} of {len(endpoints)} "
            f"proxies unreachable, starting Ansible anyway: {names}"
        )
    else:
        log(f"all {len(endpoints)} managed-ssh proxies reachable after {elapsed:.1f}s")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as error:  # noqa: BLE001 - a broken gate must not wedge a working run
        log(f"unexpected error, starting Ansible anyway: {error!r}")
