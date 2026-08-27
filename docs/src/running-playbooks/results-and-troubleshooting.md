# Reading results and troubleshooting

The operator reports everything about a run on the plan's `.status`. There is no separate dashboard,
and you do not need pod logs — the per-host recap travels back via the Job container's termination
message, so `kubectl` is enough. For a durable history of *past* runs, the operator also records a
[`Play`](#run-history) per run attempt.

## At a glance

The `PlaybookPlan` has printer columns, so a quick look is:

```sh
kubectl get playbookplan -n my-team
# NAME            MODE        SCHEDULE     PREVIOUS RUN  NEXT RUN  CURRENT HASH  READY  RUNNING  SUMMARY          PHASE       AGE
```

For detail, `kubectl describe playbookplan <name>` (or `-o yaml`) shows the phase, conditions,
per-host status, and the summary line.

## Phases

`.status.phase` is one of:

| Phase | Meaning |
|---|---|
| `Pending` | Triggers not yet evaluated — the resting state right after creation or after the inputs changed. |
| `Delayed` | Execution was deferred (e.g. waiting on proxy readiness). Transient. |
| `Applying` | A Job is running the playbook right now. The `Running` condition is `True`. |
| `Scheduled` | (`Recurring`) The run finished and the plan is waiting for the next schedule tick. |
| `Succeeded` | (`OneShot`) Every host has succeeded on the current hash; the plan is quiet until the inputs change. |
| `Failed` | (`OneShot`) The run finished but some host could not be brought current. Also used when the plan is refused outright — see [the plan's name is too long](#the-plans-name-is-too-long). |
| `UnauthorizedNamespace` | The plan's namespace is not enrolled for the operator — it will not run. See below. |

## Conditions

`.status.conditions` carries `True`/`False` conditions. `Ready` and `Running` are also surfaced as
printer columns:

- **`Ready`** — the plan is in a healthy, settled state.
- **`Running`** — a Job is currently applying the playbook.
- **`Blocked`** — the run is due but waiting on a per-host lock held by another run; the condition
  message names the host and the run holding it. This one is not a column — read it with `kubectl
  describe` or `-o yaml`. It clears on its own once every lock the run needs is free. See
  [Host locks](./scheduling-and-modes.md#host-locks).

`.status.summary` is a one-line human summary (also a column), and `.status.currentHash` is the
current [execution hash](./scheduling-and-modes.md#drift-detection).

## Per-host outcomes

`.status.hostsStatus` maps each targeted host to its result. `lastOutcome` is one of:

| Outcome | Meaning |
|---|---|
| `Succeeded` | Ansible applied the playbook to this host successfully. `lastAppliedHash` is bumped to the current hash. |
| `Failed` | Ansible reached the host but a task failed. |
| `NotReached` | The host was in scope but Ansible never got to it — e.g. an earlier host in its `serial` batch stopped the play. Not an error *on this host*. |
| `Unknown` | The operator could not read a recap for this host — its **own instrumentation** failed, not Ansible. Distinct from `NotReached`. Worth investigating (see below). |

Each host also records `lastAppliedHash` (the hash it last *succeeded* on — this is what drift
detection compares against) and `lastTransitionTime`.

## Run history

The plan's `.status` only reflects the **current** run. For a durable, per-attempt history, the
operator records a `Play` for every run attempt — one `Play` per Job, in the plan's namespace, owned
by the plan (so they are removed when you delete it). Unlike the run's Job, which Kubernetes reaps
shortly after it finishes (`spec.ttlSecondsAfterFinished`), a `Play` keeps the recap for as long as
retention allows.

```sh
kubectl get plays -n my-team
# NAME                        PLAN        HOSTS  OK  CHANGED  FAILED  UNREACHABLE  STATUS     AGE
# apply-web-config-a1b2c3-1   web-config      3   0        0       2            0  Failed      9m
# apply-web-config-a1b2c3-2   web-config      3  12        3       0            0  Succeeded   8m
```

The columns mirror the Ansible **recap**, summed across every host the run targeted. `kubectl get
plays -o wide` adds the less-common counters (`rescued`, `skipped`, `ignored`) and the attempt
number. Each `Play`'s `.status` also carries the per-host recap and outcome plus `finishedAt`:

```sh
kubectl get play apply-web-config-a1b2c3-2 -n my-team -o yaml
```

A `Play`'s `.status.phase` is `Running`, `Succeeded`, `Failed`, or `Unknown` (the recap could not be
read — same meaning as the per-host [`Unknown`](#hosts-show-unknown) outcome).

### How many are kept

Retention is per plan and split by outcome, so failures stay visible longer than successes:

| Field | Default | Keeps |
|---|---|---|
| `spec.successfulPlaysHistoryLimit` | 3 | most recent **succeeded** Plays |
| `spec.failedPlaysHistoryLimit` | 10 | most recent **failed / unknown** Plays |

Plays beyond these limits are pruned automatically as new runs finish. Deleting the `PlaybookPlan`
removes all of its Plays.

## Troubleshooting

### The plan is stuck in `UnauthorizedNamespace`

The plan's namespace has not been **enrolled** with the operator, so the operator has no RBAC to read
its Secrets or create its Job and refuses to run it (fail-closed). This is a cluster-admin action,
not something you can fix from the tenant side: an admin must add your namespace to the chart's
`watchNamespaces` and roll the operator. See
[Deployment → enrolled namespaces](../cluster-operators/deployment.md#enrolled-namespaces).

### A `ClusterInventory` resolves to zero hosts

If Nodes clearly match your selector but the plan still targets nothing, the likely cause is that no
`NodeAccessPolicy` grants your namespace those Nodes. Node access is **fail-closed**: with no matching
policy a namespace may reach no Nodes at all. Check `.status.eligibleHosts` on the plan and ask your
admin which policy applies to your namespace (see
[Node access policies](../cluster-operators/node-access-policies.md)). The `ClusterInventory`'s own
`.status.hostCount` shows how many Nodes match *before* policy clamping, which helps localise the
problem.

### The plan's name is too long

The plan is `Failed` and its summary reads **"name is N characters; a PlaybookPlan name must be at
most 63 …"**. Applying such a plan is normally rejected outright; you only see this state on a
cluster that does not enforce CRD validation rules. Either way nothing is created for the plan.

The name is used as a label value on every object a run creates, and Kubernetes label values stop at
63 characters. An object's name cannot be changed, so recreate the plan under a shorter one — a
`kubectl edit` will not clear this.

### A plan is not starting and its `Blocked` condition is `True`

Another run is holding a lock on a host this plan targets, so the plan is waiting its turn — host
locks are cluster-wide, and a Node is applied to by one run at a time (see
[Host locks](./scheduling-and-modes.md#host-locks)). `kubectl describe playbookplan <name>` shows the
host and the run holding it, and the operator logs a matching warning. This is normal when two plans
share hosts: the run proceeds once the other finishes. If it never clears, look at the run named as
the holder — a plan that runs very often (a `Recurring` plan on a tight schedule, or a `OneShot` that
keeps failing and retrying) can keep an overlapping plan waiting for a long time.

### Hosts show `NotReached`

Expected when a play stops early — for example a `serial` batch that failed before reaching later
hosts, or a `run_once` task that aborted. Fix the host that actually failed (its outcome is `Failed`);
the `NotReached` hosts should proceed on the next run.

### Hosts show `Unknown`

This means the operator could not parse a recap for the host — the operator's instrumentation, not
the playbook, is the suspect. Common causes: the run image is missing something the recap callback
needs, or the Job pod was killed before it could write its termination message (a disruptive playbook
that took down its own runner is one way). Inspect the (not-yet-reaped) Job pod; raising
`spec.ttlSecondsAfterFinished` buys time to look before it is cleaned up.

### A change is not being picked up

Only inputs that feed the [execution hash](./scheduling-and-modes.md#drift-detection) — the playbook
text and the **contents** of referenced Secrets — trigger a re-run of already current hosts. Editing
an unrelated `spec` field (or a schedule that has not fired yet) will not. Confirm
`.status.currentHash` actually changed after your edit.

### It never seems to run

Check the `schedule`/`timeZone` and `.status.nextRun`. Remember that `OneShot` goes quiet once every
host is current — that is success, not a hang. A `Recurring` plan with no `schedule` has nothing
telling it when to fire. If the `Blocked` condition is `True`, it is waiting on host locks held by
another run — see above.
