# Ansible Operator

An opinionated runner for Ansible on Kubernetes, inspired by Rancher's [system-upgrade-controller](https://github.com/rancher/system-upgrade-controller).

Describe *what* should be applied and *where* as Kubernetes resources; the operator renders the
inventory, runs `ansible-playbook` in a Job, reaches your hosts, and records per-host outcomes back
onto the resource's status — on a schedule, idempotently, and without a standing privileged agent
on your nodes.

## How it works

You create three kinds of custom resource:

- **`PlaybookPlan`** — the playbook to run, which inventories to run it against, its schedule and
  execution mode, plus variables and files. This is the thing the operator reconciles.
- **`ClusterInventory`** — a set of host groups resolved dynamically from cluster **Node** labels.
- **`StaticInventory`** — a set of host groups given as literal hostnames/IPs, with the SSH
  credentials used to reach them.

For each run the operator renders a workspace (playbook, inventory, variables, recap callback) into
a Secret, ensures the hosts are reachable, and launches a single Job that applies the playbook to
every targeted host. When the Job finishes it parses a compact per-host recap and updates the
`PlaybookPlan` status.

## Features

- [x] **Dynamic node-based inventories** — build inventories from cluster Nodes matched by labels
  and match-expressions (`ClusterInventory`).
- [x] **Static hostname-based inventories** — build inventories from arbitrary hostnames or IPs
  with their own SSH credentials (`StaticInventory`).
- [x] **Agentless node access via managed SSH** — cluster nodes are reached through short-lived,
  per-run sshd *proxy* pods rather than a standing privileged DaemonSet. The operator runs its own
  SSH certificate authority, mints an ephemeral per-node host certificate, and each session
  `nsenter`s into the node's host namespaces. Proxy pods exist only for the duration of a run and
  are torn down afterwards, and their ingress is locked to that run's Job by a NetworkPolicy.
- [x] **Direct SSH to static hosts** — reach non-cluster hosts with a user-supplied key
  (`spec.ssh.secretRef`).
- [x] **Mixed inventories in one run** — a single `PlaybookPlan` can target both cluster nodes
  (managed SSH) and external hosts (direct SSH) in one Job and one rendered inventory.
- [x] **Scheduling** — 5-field cron `schedule` with an explicit `timeZone`; runs fire inside a
  short time window around each scheduled tick.
- [x] **Execution modes** — `OneShot` (run until every host has succeeded exactly once, then stop)
  and `Recurring` (re-run on every schedule tick).
- [x] **Idempotency / drift detection** — an execution hash over the playbook plus every referenced
  Secret decides which hosts are out of date; only those are (re)applied, and a host that already
  succeeded on the current hash is skipped.
- [x] **Per-host mutual-exclusion locking** — Kubernetes Leases ensure two runs never operate on
  the same host concurrently.
- [x] **Per-host outcome reporting** — the plan's status carries a per-host outcome
  (Succeeded / Failed / NotReached / Unknown), `Ready`/`Running` conditions, and a summary. The
  recap travels via the Job container's termination message, so the operator never needs to scrape
  pod logs.
- [x] **Scheduling-aware placement** — the ansible Job pod softly prefers *not* to be scheduled onto
  a node the run targets, so a disruptive playbook is less likely to kill its own controller pod
  mid-run (never blocks scheduling, even when a run targets every node).
- [x] **Secrets as variables** — Kubernetes Secrets can be mounted as Ansible variables.
- [x] **Volumes as files** — use [image volumes](https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/)
  to make blobs (binaries, archives) available at runtime without rebuilding the runtime image.\*

\* Image volumes are a comparatively new Kubernetes feature and are not yet supported by every
container runtime.

## Example

```yaml
apiVersion: ansible.cloudbending.dev/v1beta1
kind: ClusterInventory
metadata:
  name: cluster-nodes
spec:
  hosts:
    - name: workers
      matchExpressions:
        - { key: node-role.kubernetes.io/control-plane, operator: DoesNotExist }
  tolerations:
    - operator: Exists
---
apiVersion: ansible.cloudbending.dev/v1beta1
kind: PlaybookPlan
metadata:
  name: patch-workers
spec:
  image: docker.io/serversideup/ansible-core:2.18
  mode: Recurring
  schedule: "0 3 * * *"
  timeZone: Europe/Berlin
  inventoryRefs:
    - clusterInventory: cluster-nodes
  template:
    playbook: |
      - hosts: all
        tasks:
          - name: Upgrade all packages
            ansible.builtin.apt:
              upgrade: dist
              update_cache: true
```

More examples live under [`examples/v1beta1/`](examples/v1beta1/).

## Installation

The operator ships as a Helm chart under [`chart/`](chart/) and release charts are published to
GHCR:

```sh
helm install --create-namespace -n ansible-system ansible-operator \
  oci://ghcr.io/webd97/charts/ansible-operator \
  --version <version>
```

It must be installed into its own dedicated namespace, which also needs the `privileged` Pod
Security Admission label because the managed-SSH proxy pods use `hostPID` and elevated
capabilities. See [`chart/README.md`](chart/README.md) for install instructions, the Pod Security
Admission and SELinux notes, and how to regenerate the bundled CRDs.

## Example use cases

- Upgrade k3s or the OS on all cluster nodes on a schedule
- Manage node-level configuration files
- Roll out node changes gradually, gated by per-host success
- Configure external (non-cluster) devices, e.g. exporting cert-manager certificates to them
