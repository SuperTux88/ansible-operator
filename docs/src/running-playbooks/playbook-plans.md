# Playbook plans

A `PlaybookPlan` is the central resource the operator reconciles. It ties a **playbook** to a set of
**inventories**, a **schedule**, and an **execution mode**, and it is where per-host results are
reported. This page explains how the fields fit together; the full field list and defaults live in
the CRD schema (`ansible-operator crds`) and the generated API reference.

## Spec fields

| Field | Required | Meaning |
|---|---|---|
| `image` | yes | An OCI image that has `ansible-playbook` and every collection your playbook uses. The Job runs this image. |
| `securityContext` | no | Container security context applied to the playbook and collection-installer containers. |
| `serviceAccountName` | no | ServiceAccount the run's pod uses, so tasks can reach the Kubernetes API. Unset means no API token is mounted — see [Managing Kubernetes resources](#managing-kubernetes-resources). |
| `inventoryRefs` | yes | Which inventories to target — one entry per referenced `ClusterInventory` or `StaticInventory`. |
| `template.playbook` | yes | The playbook text itself (see below). |
| `mode` | no (`OneShot`) | `OneShot` or `Recurring` — see [Scheduling and execution modes](./scheduling-and-modes.md). |
| `schedule` | no | A 5-field cron expression gating when the plan may run. Omit for "as soon as possible". |
| `timeZone` | no (UTC) | IANA time zone the `schedule` is evaluated in, e.g. `Europe/Berlin`. |
| `suspend` | no (`false`) | Pause switch, like a CronJob's `suspend`: while `true` the operator starts no new runs. See [Suspending a plan](./scheduling-and-modes.md#suspending-a-plan). |
| `template.variables` | no | Variables made available to the playbook — see [Variables and files](./variables-and-files.md). |
| `template.files` | no | Files made available at runtime — see [Variables and files](./variables-and-files.md). |
| `template.requirements` | no | An Ansible `requirements.yml` (e.g. collections) installed before the run. |
| `ttlSecondsAfterFinished` | no | How long a finished run's Job and pod are kept before Kubernetes reaps them. Values below 60s are raised to 60. |
| `verbosity` | no (`0`) | `ansible-playbook` verbosity, `0`–`4`, mapped to `-v`…`-vvvv`. Affects log detail only. |

## Choosing the image

The operator does **not** ship Ansible; your `image` provides it. Pick or build an image that
already contains `ansible-playbook` plus every collection and Python dependency your tasks need.
Community images such as `docker.io/serversideup/ansible-core:<version>` work well as a base. If your
playbook needs collections that are not baked into the image, list them under `template.requirements`
and they are installed before the playbook runs:

```yaml
template:
  requirements: |
    collections:
      - name: community.general
        version: ">=6.0.0"
  playbook: |
    - hosts: all
      tasks: []
```

Baking collections into the image is faster and more reproducible than installing them on every run;
use `requirements` for collections you cannot or do not want to pre-bake.

The execution image also determines which container security settings it supports. Configure them
on the plan so they stay coupled to that image:

```yaml
spec:
  image: docker.io/serversideup/ansible-core:2.18
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    seccompProfile:
      type: RuntimeDefault
```

The context is applied to both the `ansible-playbook` container and the optional
`download-collections` init container. Changing the security context affects future Jobs but does
not itself cause hosts that already succeeded to run again.

## The playbook

`template.playbook` is an ordinary Ansible playbook as a YAML string. Two conventions matter:

- **Target `hosts: all`** or a group name from your inventories. The operator renders the inventory
  for you; your playbook selects hosts out of it. Every host from every referenced inventory group is
  present, grouped by the group `name` you gave it.
- The operator injects the inventory and connection variables automatically. Do **not** set
  `ansible_host`, `ansible_user`, `ansible_ssh_private_key_file`, connection ports, or host-key
  settings — those are rendered from the inventories and, for cluster nodes, the managed-SSH
  machinery. Setting them yourself conflicts with the operator.

The playbook text is parsed as YAML when the plan is reconciled, so a syntactically broken playbook
surfaces as an error early rather than as a failed Job.

## Referencing inventories

`inventoryRefs` is a list; each entry names **exactly one** inventory by kind:

```yaml
inventoryRefs:
  - clusterInventory: cluster-nodes        # a ClusterInventory in this namespace
  - staticInventory: edge-appliances       # a StaticInventory in this namespace
```

Inventories are resolved from the **same namespace** as the plan. The groups they define become
Ansible groups in the rendered inventory, so a playbook can target `hosts: workers` or
`hosts: edge-appliances` as well as `hosts: all`.

## Managing Kubernetes resources

By default the run's pod carries **no** Kubernetes API token, so a playbook cannot talk to the
cluster's API. To let tasks manage Kubernetes resources (via `kubernetes.core` or `kubectl`), set
`serviceAccountName` to a ServiceAccount in the plan's namespace. The operator then runs the pod as
that ServiceAccount and mounts its token; Ansible's `kubernetes.core` modules pick it up through
in-cluster configuration automatically, so you do not supply a kubeconfig.

You own the identity and its permissions: create the ServiceAccount and a `Role`/`RoleBinding` (or
`ClusterRoleBinding`) granting exactly what the playbook needs, and make sure your `image` includes
the `kubernetes.core` collection. Grant the least privilege that works — the playbook runs with
whatever RBAC you bind to this ServiceAccount.

```yaml
spec:
  serviceAccountName: deploy-bot
```

## Log verbosity

`verbosity` raises how much `ansible-playbook` logs, from `0` (no `-v` flag) up to `4` (`-vvvv`);
higher values are clamped to `4`. Use it when you need to see task-level or connection detail while
troubleshooting. It changes log output only — it is not part of the execution hash, so raising or
lowering it never re-runs the playbook on hosts that are already current.

## One Job per run

Each run is a single Kubernetes Job (named `apply-<plan>-<id>-<retry>`) that applies the playbook to
all of that run's hosts together, not one Job per host. This lets a playbook use Ansible features
that span hosts (`serial`, `run_once`, delegation) normally. The operator adds per-host **Leases** so
two runs never touch the same host at once, and it steers the Job's own pod away from the Nodes the
run targets, so a disruptive playbook is less likely to evict its own runner mid-run.

## Lifecycle at a glance

A plan moves through phases: `Pending` → `Applying` → `Succeeded`/`Failed` (for `OneShot`) or
`… → Scheduled → …` (for `Recurring`). Drift detection decides *which* hosts actually run: an
execution hash over the playbook plus every referenced Secret marks hosts out of date, and a host
that already succeeded on the current hash is skipped. See
[Scheduling and execution modes](./scheduling-and-modes.md) for the mechanics and
[Reading results](./results-and-troubleshooting.md) for how to read the outcome.
