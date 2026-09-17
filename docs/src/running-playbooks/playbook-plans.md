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
| `image` | yes | An OCI image that has `ansible-playbook` on `PATH`, `python3` on `PATH`, and every collection your playbook uses. The Job runs this image. |
| `securityContext` | no | Container security context applied to the playbook and collection-installer containers. |
| `serviceAccountName` | no | ServiceAccount the run's pod uses, so tasks can reach the Kubernetes API. Unset means no API token is mounted — see [Managing Kubernetes resources](#managing-kubernetes-resources). |
| `inventoryRefs` | yes | Which inventories to target — one entry per referenced `ClusterInventory` or `StaticInventory`. |
| `provides` | no | Declares what this plan makes true on the hosts it converges, so other plans can depend on it — see [Declaring what a plan provides](#declaring-what-a-plan-provides). |
| `template.playbook` | yes | The playbook text itself (see below). |
| `mode` | no (`OneShot`) | `OneShot` or `Recurring` — see [Scheduling and execution modes](./scheduling-and-modes.md). |
| `maxAttempts` | no (`3` / `1`) | How many times a failed run may be tried again, counting the first run. Defaults to `3` for `OneShot` and `1` for `Recurring` — see [Retries](./scheduling-and-modes.md#retries). |
| `schedule` | no | A 5-field cron expression (`minute hour day-of-month month day-of-week`) gating when the plan may run. Seconds and year fields are not supported. Omit for "as soon as possible". |
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

### `python3` must be on `PATH`

Two commands are run from your image, and both must resolve on `PATH`: `ansible-playbook`, and
`python3` for the [preflight connectivity check](./cluster-nodes.md#preflight-connectivity-check)
that runs before Ansible on plans targeting cluster Nodes. The operator reuses your image for that
check rather than pulling one of its own, which keeps a run to a single image — and Ansible is itself
a Python program, so an image that can run `ansible-playbook` practically always ships an
interpreter.

Practically always is not always, though. If Ansible is installed into a virtual environment that is
not on the image's `PATH`, or the interpreter is only reachable as `python`, the check cannot start:
the init container exits immediately, `ansible-playbook` never runs, and the run finishes with no
recap — every host reported [`Unknown`](./results-and-troubleshooting.md#hosts-show-unknown). Verify
it the way the Job will:

```sh
podman run --rm <your-image> python3 --version
```

If it fails, add a `python3` to the image or symlink the interpreter you have onto `PATH` under that
name. Plans that target only `StaticInventory` hosts never run the check and are unaffected.

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

The context is applied to every container of the run: the `ansible-playbook` container, the
optional `download-collections` init container, and the `managed-ssh-preflight` init container that
plans targeting cluster Nodes get. Changing the security context affects future Jobs but does not
itself cause hosts that already succeeded to run again.

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

## Declaring what a plan provides

Some plans only make sense after another one has finished on the same host: a container runtime has
to be configured before something that uses it is deployed, a driver installed before a workload
that needs it lands. `spec.provides` is how the first plan says so.

```yaml
spec:
  provides:
    version: "1.4.2"
```

Every cluster Node this plan applies to **successfully** is then labelled

```
<namespace>.plan.ansible.cloudbending.dev/<plan-name>: <version>
```

so a plan in namespace `platform` named `containerd-config` writes
`platform.plan.ansible.cloudbending.dev/containerd-config: "1.4.2"`. You do not choose the key: it
is derived from the plan's own namespace and name, which is what keeps one plan from claiming
another's label or labelling its way into Nodes it was never granted. A plan without `provides` is
labelled nowhere.

Dependent plans select on that label in their own `ClusterInventory` — see
[Cluster nodes](./cluster-nodes.md#depending-on-another-plan). Ordinary workloads can use it too, in
an ordinary `nodeAffinity`: "schedule this only where the driver playbook succeeded".

### The version is part of the execution hash

Changing `version` changes the plan's revision, so the playbook **re-runs on every host** before any
label moves. That is deliberate, and it is what makes the label worth trusting: a Node carrying
`1.4.2` has had a run of the revision that declared `1.4.2` succeed on it. Adding `provides` to an
existing plan re-runs it once, and so does removing it.

Two consequences worth planning for:

- A version that follows your chart version re-runs the playbook on every release. If that is not
  what you want, give the plan a version of its own that you bump when the thing it installs
  actually changes.
- It is the only way to force a re-run when the playbook text has not changed — for instance when
  the tool it installs lives in the plan's `image`, which is not part of the hash.

SemVer build metadata cannot be expressed, because `+` is not a legal label value character. Follow
Helm's own `helm.sh/chart` convention and write it as `_`, e.g. by piping a chart version through
`replace "+" "_"`.

### What the label means

It means **"this version was applied here at some point"** — not that the last run was green, and
not that the host is currently healthy. Specifically:

- A later run that *fails* on a host leaves the previous label standing. The software is still
  there; a failure does not undo it.
- A host that leaves this plan's inventory keeps its label, for the same reason.
- A Node that is deleted and re-registered under the same name is **not** labelled until the plan
  has run on the new machine. A fresh Node inherits the name and nothing else.
- Only cluster Nodes take part. `StaticInventory` hosts cannot — there is no Kubernetes object to
  label. See [External hosts](./external-hosts.md).

### When the labels are removed

A label is never withdrawn because a run went badly — only when the plan stops claiming it:

- **You remove `provides` from the spec.** The labels go on the next tick. (Because the version is
  part of the hash, this also re-runs the playbook once; harmless for an idempotent playbook.)
- **You delete the plan.** Its labels are removed within seconds, and deleting is never blocked
  waiting for that — if the operator is down at the time, it cleans them up when it next starts.
- **Your namespace is un-enrolled** by an administrator. The operator refuses to run the plan at
  all, so its claim is withdrawn too and dependents elsewhere lose those hosts. Re-enrolling
  restores the labels from the recorded results on the first tick, **without** re-running anything.

### Seeing how far the label has reached

A providing plan carries a `ProvidesLabels` condition saying what it publishes and how far it has
got:

```text
publishing platform.plan.ansible.cloudbending.dev/containerd=1.5.0 on 3 of 5 Node(s) for other plans
to depend on
```

The first number counts Nodes carrying this exact version; the second counts Nodes carrying the key
at any version. Right after you bump `spec.provides.version` the Nodes still carry the old value, so
the condition reads `on 0 of 5` and the first number climbs as the plan re-runs on each host. A
first number that stays short of the second once the plan has stopped running is a rollout that has
stalled — look at the per-host outcomes of the Nodes still on the old version. The first number can
also lag briefly: labels are written after the status, so Nodes relabelled in one reconcile are
counted in the plan's next one.

These counts are this plan's **reach**, and nothing more. It is not a claim about what any dependent
can use: a [`NodeAccessPolicy`](../cluster-operators/node-access-policies.md) may leave a dependent
in another namespace with fewer of those Nodes than the number here. What each dependent is actually
waiting for is on its own inventory — see
[Seeing what an inventory is waiting for](./cluster-nodes.md#seeing-what-an-inventory-is-waiting-for).

If your cluster administrator has disabled node labels (`nodeLabels.enabled=false` in the chart),
plans with `provides` still run but publish nothing, and the condition is `False` with reason
`NodeLabelsDisabled`. It then gives a single count, which means the opposite: Nodes still carrying
the label, at any version, from before the feature was switched off. They keep steering inventories, and removing them is now an
administrator's job.

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

Before the Job starts, the operator renders everything the run needs to read — the playbook, the
inventory it resolved, any inline variables — into a **workspace Secret** in the plan's namespace,
named `workspace-<truncated-plan>-<id>` and owned by the plan. The run mounts it as its working
directory, and it is rewritten in place on every run, so treat it as read-only: every key the
operator renders — `playbook.yml`, `inventory.yml`, the recap plugin, any static variables — is
overwritten, so an edit to one of those does not survive. Keys it does not render are left alone
and nothing prunes them, so a key you add, or one the operator wrote for an earlier revision and no
longer produces, stays in the run's working directory until you remove it or the Secret is
recreated. The readable plan portion is shortened as needed and any dots in it become
hyphens, so a plan named `web.prod` gets `workspace-web-prod-<id>`; the `<id>` is derived from the
plan's UID. Together they keep the name separate from the Secrets you create — including one named
after the plan itself, which is yours to use. If something else does end up at that exact name, the
operator refuses to write it rather than overwrite it, and says so in `.status.summary`. What it
checks is the owner reference: a Secret carrying one that names this plan by both name and UID is
taken to be its workspace and rewritten, anything else is refused — so a Secret of yours is only
treated as the workspace if you gave it that reference, which already means Kubernetes deletes it
with the plan. See
[A Secret already occupies the workspace Secret's
name](./results-and-troubleshooting.md#a-secret-already-occupies-the-workspace-secrets-name).

## Lifecycle at a glance

A plan moves through phases: `Pending` → `Delayed` while it waits for a scheduled start →
`Applying` → `Succeeded`/`Failed`/`HostsUnreachable`, in both modes, from the recap of the run that
just finished. `HostsUnreachable` is a failure that is not the playbook's fault: everything reachable
was applied, and what is left is a machine that is down. A `Recurring` plan keeps that result between ticks and
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
