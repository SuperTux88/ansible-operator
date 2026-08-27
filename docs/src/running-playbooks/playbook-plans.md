# Playbook plans

A `PlaybookPlan` is the central resource the operator reconciles. It ties a **playbook** to a set of
**inventories**, a **schedule**, and an **execution mode**, and it is where per-host results are
reported. This page explains how the fields fit together; the full field list and defaults live in
the CRD schema (`ansible-operator crds`) and the generated API reference.

A plan's **name** is capped at 63 characters, shorter than Kubernetes would otherwise allow for a
custom resource. The operator records that name as a label on every object a run creates — its
`Play`, its Job, that Job's pod, and the run's NetworkPolicy — and Kubernetes label values stop at 63
characters. A longer name is rejected when you apply it; if your cluster does not enforce CRD
validation rules, the operator refuses the plan instead and says so in `.status.summary`.

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

Each run is a single Kubernetes Job (named `apply-<plan>-<id>-<n>`) that applies the playbook to
all of that run's hosts together, not one Job per host. This lets a playbook use Ansible features
that span hosts (`serial`, `run_once`, delegation) normally. The operator adds per-host **Leases** so
two runs never touch the same host at once, and it steers the Job's own pod away from the Nodes the
run targets, so a disruptive playbook is less likely to evict its own runner mid-run.

## Lifecycle at a glance

A plan moves through phases: `Pending` → `Delayed` while it waits for a scheduled start →
`Applying` → `Succeeded`/`Failed`, in both modes, from the recap of the run that just finished. A `Recurring` plan keeps that result between ticks and
advertises the next one through `.status.nextRun`. Drift detection decides *which* hosts actually run: an
execution hash over the playbook plus every referenced Secret marks hosts out of date, and a host
that already succeeded on the current hash is skipped. See
[Scheduling and execution modes](./scheduling-and-modes.md) for the mechanics and
[Reading results](./results-and-troubleshooting.md) for how to read the outcome.

`Applying` covers the whole active run, including waiting for host locks and proxy readiness.
The `Running` condition distinguishes the narrower period when the Job itself is active.

## Deleting a plan

Deleting a plan **cancels** the run it has in flight — the run is not allowed to finish first. The
plan object then stays in `Terminating` for a moment while the operator tears the run down, because
it holds a `ansible.cloudbending.dev/run-cleanup` finalizer:

1. the run's Job is cancelled with a foreground deletion, and the operator waits for the Job and then
   its pod to actually be gone;
2. the run's managed-ssh proxy pods, their NetworkPolicy and Secret are deleted;
3. the run's host Leases are released;
4. the finalizer is removed and the plan disappears.

The wait in step 1 is what makes this safe: the run's host locks keep being renewed until its pod is
gone, so no other plan can start against a host while a playbook may still be talking to it. A
foreground deletion is what makes the Job's own disappearance mean that — Kubernetes keeps the Job
object until it has deleted the pods it owns, so the operator never has to infer from a single
snapshot that a pod it cannot see will not appear a moment later. A plan that stays `Terminating` for
a long time is therefore usually a pod that will not stop — look at the Job's pod, and at the
operator log, which names the run it is waiting on.

The finalizer is only present while a plan actually holds a run, and a plan that has never started
one never carries it at all. Deleting an idle plan is immediate — with one exception: a plan gives
the finalizer back on the tick *after* the one that released its run, so a plan whose run has just
finished, or whose run was interrupted before it created anything, holds it for one more tick. If
the operator stops inside that moment, even an idle plan waits in `Terminating` until it returns.

Everything a run creates in the plan's own namespace (its Job, `Play` records, workspace Secret,
client-certificate Secret and egress NetworkPolicy) is owned by the plan and would be removed by
Kubernetes anyway. The finalizer exists for what lives in the **operator's** namespace — proxy pods
and host Leases — which no owner reference can reach across namespaces, and which nothing but this
operator can release.

> **Do not strip the finalizer to force a deletion.** Removing `ansible.cloudbending.dev/run-cleanup`
> by hand makes the plan disappear immediately and strands exactly the resources it protects: a
> node-root proxy pod that keeps running, and a host Lease held by a run that no longer exists.
>
> If you have to do it, **write the run's identity down first**. The plan's `Play` records and its
> Job are owned by the plan and are deleted with it, so the moment it disappears there is nothing
> left in its namespace that names the run — while the proxy pods and Leases in the operator's
> namespace are found by exactly those values:
>
> ```sh
> kubectl get playbookplan my-plan -n my-team -o jsonpath='{.status.activeRun}'
> ```
>
> Keep the `runId`, `executionHash` and `jobName` it prints, along with the plan's name and
> namespace, and clean the run up afterwards with the [manual
> procedure](./results-and-troubleshooting.md#the-plan-is-stuck-in-applying). If the plan is already
> gone and nothing was captured, see [orphaned run resources with no
> plan](./results-and-troubleshooting.md#orphaned-run-resources-with-no-plan).
