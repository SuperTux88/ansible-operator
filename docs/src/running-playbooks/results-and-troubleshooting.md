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

When a plan changes during `Applying`, `.status.currentHash` shows the newly desired revision while
`.status.activeRun` identifies the older run still being completed. The operator keeps renewing its
host locks and removes its run-specific proxy infrastructure before starting the replacement. This
prevents an old Job and a new revision from targeting the same host concurrently.

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
operator records a `Play` before creating the attempt's Job, in the plan's namespace and owned by the
plan (so they are removed when you delete it). Once an attempt launches, its `Play` corresponds to
exactly one Job; an attempt abandoned during preparation never creates one. Unlike a launched run's
Job, which Kubernetes reaps shortly after it finishes (`spec.ttlSecondsAfterFinished`), a `Play` keeps
the recap for as long as retention allows. Its spec preserves the plan UID, execution hash,
per-attempt run ID, target inventory, preparation-input fingerprint, attempt, and schedule slot, and
is rejected for update once written. It records the run's *identity*, not a copy of the plan: what the
run executes is re-derived from the plan and its inventories, and the fingerprint is what tells the
operator whether those are still the same ones the run was prepared for. The operator creates this
record before infrastructure and correlates the Job and pod back to the Play UID, so restart recovery
does not infer run identity from mutable labels.

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

A `Play`'s `.status.phase` is normally `Prepared`, `Starting`, `Launching`, `Running`, `Succeeded`,
`Failed`, or `Unknown`. `Prepared` means the run identity has been recorded and the run is still
waiting for its host locks — nothing has been created for it yet, so it stays abortable. `Starting`
means the locks are held and the run's proxy infrastructure is being set up. `Launching` means Job
creation was committed; if the Job is absent, recovery re-verifies the locks, proxy infrastructure,
and live node authorization before creating it. `Unknown` means the Job ran but its recap could not be
read — the same meaning as the per-host [`Unknown`](#hosts-show-unknown) outcome. You may also briefly
catch `Aborted`: the internal cleanup phase of an attempt that was given up before its Job existed.
Such a record is deleted once its resources are released, so a superseded attempt is never left behind
as a failed or unknown execution.

Which attempts can be given up that way — and which are always left to finish — is one rule, covered
in [Editing a plan while a run is in
flight](./scheduling-and-modes.md#editing-a-plan-while-a-run-is-in-flight).

### How many are kept

Retention is per plan and split by outcome, so failures stay visible longer than successes:

| Field | Default | Keeps |
|---|---|---|
| `spec.successfulPlaysHistoryLimit` | 3 | most recent **succeeded** Plays |
| `spec.failedPlaysHistoryLimit` | 10 | most recent **failed / unknown** Plays |

Plays beyond these limits are pruned automatically as new runs finish. The operator also retries the
retention pass on ordinary reconciles if a deletion fails, so a temporary API error does not
permanently leave old records behind. Deleting the `PlaybookPlan` removes all of its Plays.

Only *finished* Plays are counted against the history limits, and a finished one is temporarily kept
until its result has been folded into the plan — so the limits can never discard the only surviving
copy of a run's recap. Once acknowledged, an old record whose deletion failed remains eligible for
the next retention pass, including when a history limit is zero. An `Aborted` record is deleted after
its resources are cleaned up rather than by history pruning. If cleanup keeps failing, the record
deliberately remains as the retry handle for resources that may still be privileged. Deleting a Play by
hand is safe once its
`.status.planStatusRecorded` is `true`, which is the operator's own marker that the run's results have
reached the plan. Deleting one that still describes a live run — or a finished one whose results have
not been folded in yet — is not, because that record is the only thing the run can be recovered from.
See [The plan is stuck in `Applying`](#the-plan-is-stuck-in-applying).

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

### The plan is stuck in `Applying`

- **"waiting for Job … which does not carry this run's identity"** — a Job with the name this run
  expects exists, but it is not the one this run created. This normally means a Job was created or
  edited outside the operator; a very unlikely generated-name collision can produce the same symptom
  after an older `Play` was pruned while its Job was still retained. The operator will not adopt the
  Job or modify it. For a run that had already reached `Running`, it waits for that Job to finish or be
  removed; then its locks and proxy pods are cleaned up and its hosts are reported
  [`Unknown`](#hosts-show-unknown), since the recap of a Job the operator did not create is not this
  run's to read, and the plan carries on. For a `Launching` run, even a finished foreign Job still
  occupies the recorded name, so the Job must be removed; if the run is still wanted, the operator
  then creates its own Job, otherwise it abandons the unlaunched run.

  An administrator should first confirm that the Job is really foreign, then delete that **exact Job**
  if it is safe to stop it. Do not delete the `Play`, its Leases, or the operator's proxy resources as
  a first step: they are the recovery handle and the protection against another run using the same
  hosts. Set the identifiers from the plan and its active `Play`:

  ```sh
  PLAN_NAMESPACE=my-team
  PLAN=my-plan

  if ! JOB=$(kubectl get playbookplan "$PLAN" -n "$PLAN_NAMESPACE" \
    -o jsonpath='{.status.activeRun.jobName}'); then
    printf '%s\n' "could not read the PlaybookPlan; this section does not apply" >&2
  elif [ -z "$JOB" ]; then
    printf '%s\n' "no active run recorded; this section does not apply"
  else
    PLAY="$JOB"

    kubectl get play "$PLAY" -n "$PLAN_NAMESPACE" -o yaml
    kubectl get job "$JOB" -n "$PLAN_NAMESPACE" -o yaml
  fi
  ```

  Compare the Job with the `Play` and plan. For the Job to be the operator's own Job, its own metadata
  must carry an owner reference identifying the plan by both name and UID, the plan name, component,
  run's hash, and run ID as labels, and the `Play`'s UID as an annotation. Its pod template must carry
  the run ID, hash, and `Play` UID as well, plus the plan name and the `playbook` component. The Job's
  name must also be the one recorded by the `Play`, including the trailing attempt number, which is
  where the operator reads the attempt from. Any mismatch confirms that the Job is foreign. A Job that
  happens to copy every one of these fields is indistinguishable from an operator-created Job at the
  Kubernetes object level, which is why
  enrolled-namespace Job creation must be protected by administrator RBAC or admission controls (see
  [the Job trust boundary](../cluster-operators/security.md#the-job-trust-boundary)).

  If the Job is foreign and its owner confirms that deleting it will not interrupt unrelated work,
  remove only that exact Job. This may stop its pods, so check its status and owner before running the
  command:

  ```sh
  kubectl get job "$JOB" -n "$PLAN_NAMESPACE" \
    -o 'custom-columns=NAME:.metadata.name,OWNER:.metadata.ownerReferences[*].name,COMPLETION:.status.completionTime,FAILED:.status.failed'
  kubectl delete job "$JOB" -n "$PLAN_NAMESPACE" --cascade=background --wait=true
  kubectl get job "$JOB" -n "$PLAN_NAMESPACE"  # expected: NotFound
  ```

  The operator will observe the free name on its next reconcile. It either creates the recorded
  `Launching` run's Job or finalizes a run that had already been running as `Unknown`, then cleans up
  its own proxy resources and Leases. If the plan remains stuck after the foreign Job is gone, inspect
  the new `.status.summary` and operator logs rather than deleting the `Play`; it may be reporting a
  separate cleanup or API-permission problem.
- **"aborted the run: its nodes are no longer granted to this namespace"** — the run's
  `NodeAccessPolicy` grant was withdrawn while it was being set up, so it was abandoned before its
  playbook could reach those nodes. Its locks and proxy pods are released and the plan re-evaluates.
  See [Node access policies](../cluster-operators/node-access-policies.md).
- **"aborted the run: it may no longer start (the desired revision changed or it missed its schedule
  window)"** and **"aborted the run: it may no longer launch and its Job was never created"** — the
  ordinary supersede path: the plan was edited (or its resolved nodes changed) while an attempt was
  still preparing. The second wording is the same decision for an attempt that had already committed
  to launching, once the API server confirmed its Job was never created. See [Editing a plan while a
  run is in flight](./scheduling-and-modes.md#editing-a-plan-while-a-run-is-in-flight).
- **"aborted the run: the plan was suspended before its Job was created"** — `spec.suspend` was set
  while an attempt was still preparing, so it was dropped rather than left to launch whenever it
  became able to. Unlike the other "aborted the run…" messages this one is a *resting* state: the
  plan goes to `Pending` and stays there until you resume it. See [Suspending a
  plan](./scheduling-and-modes.md#suspending-a-plan).
- **"released the abandoned run …"** — cleanup of an attempt abandoned by an earlier tick has now
  finished. Only seen after a "could not release the abandoned run …" below, or after a restart
  interrupted a teardown; the plan re-evaluates immediately.
- **"recorded a finished run; another attempt is still in flight"** — after an outage, more than one
  finished result can be waiting to be written to the plan. The operator applies them one tick at a
  time, oldest first, and says so rather than reporting the plan finished while a later attempt is
  still going. It clears on its own.

With the sole exception of the `suspend` one, every "aborted the run…" message above is a transient
state rather than a resting one: the attempt is gone and the plan re-evaluates immediately, so if the
plan stays `Applying` on one of them the *next* tick has usually already replaced it with something
else. A run that is merely pausing *before* it launches reports that through a condition instead:
`Blocked` for a contended host lock, or `WaitingForNodes` for proxy pods that are not `Ready` yet.

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

If *every* host of one run shows `Unknown` at once, the likely cause is different: the run's `Play`
was deleted while the run was still live. That record is the only thing the run can be recovered
from, so the operator releases the run's locks and proxy pods and reports the whole run as unknown
rather than leaving the plan stuck. The next run reports these hosts normally.

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
