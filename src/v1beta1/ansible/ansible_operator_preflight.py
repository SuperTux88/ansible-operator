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
# eat the whole budget. Endpoints are dialled concurrently, so this is the cost of a sweep, not of
# a sweep times the number of hosts.
CONNECT_TIMEOUT_SECONDS = 2.0

# sshd sends its identification string as soon as the connection is accepted. Requiring it rules out
# a half-programmed datapath where the SYN is answered but sshd is not actually serving us yet.
BANNER_PREFIX = b"SSH-"
BANNER_BYTES = 256


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
        endpoints.append((host, address, int(port)))

    return endpoints


def reachable(address, port, timeout):
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(BANNER_BYTES)
    except OSError:
        return False

    return banner.startswith(BANNER_PREFIX)


def wait_for(endpoints, timeout):
    started = time.monotonic()
    deadline = started + timeout
    pending = list(endpoints)

    with futures.ThreadPoolExecutor(max_workers=len(endpoints)) as pool:
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            budget = min(CONNECT_TIMEOUT_SECONDS, max(remaining, 0.1))
            results = pool.map(
                lambda endpoint: reachable(endpoint[1], endpoint[2], budget), pending
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

            if pending and time.monotonic() + POLL_INTERVAL_SECONDS < deadline:
                time.sleep(POLL_INTERVAL_SECONDS)

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
