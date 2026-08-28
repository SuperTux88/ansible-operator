# Reading results and troubleshooting

The operator reports everything about a run on the plan's `.status`. There is no separate dashboard,
and you do not need pod logs — the per-host recap travels back via the Job container's termination
message, so `kubectl` is enough. For a durable history of *past* runs, the operator also records a
[`Play`](#run-history) per run.

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
| `Pending` | Triggers not yet evaluated — the resting state right after creation, after the inputs changed, while an input [cannot be read](#the-plans-inputs-cannot-be-read), or while an invalid [schedule or time zone](#the-plans-schedule-or-time-zone-is-invalid) prevents a plan with no run verdict from starting. |
| `Delayed` | The plan is waiting for its scheduled time and has no result yet under the current playbook and inputs. |
| `Applying` | A run is active: it may be waiting for host locks, preparing proxy infrastructure, or running its Job. `Running=True` means the operator has seen the run's own Job; `Running=False` with reason `JobIdentityMismatch` means another Job holds its name. |
| `Succeeded` | Every host targeted by the latest run succeeded. A `OneShot` plan is then quiet until the inputs change; a `Recurring` plan keeps this result between ticks, with `.status.nextRun` naming the next one. The verdict remains visible if an invalid [schedule or time zone](#the-plans-schedule-or-time-zone-is-invalid) prevents another run. |
| `Failed` | The latest run did not succeed on every host, or its recap could not be read. A `Recurring` plan keeps this result between ticks the same way. The verdict remains visible if an invalid [schedule or time zone](#the-plans-schedule-or-time-zone-is-invalid) prevents another run. Also used when the plan is refused outright — see [the plan's name is too long](#the-plans-name-is-too-long). |
| `UnauthorizedNamespace` | The plan's namespace is not enrolled for the operator — it will not run. See below. |

## Summary

`.status.summary` — the `Summary` printer column — is one line about the plan's hosts:

```text
5/5 up-to-date
3/5 up-to-date (2 outdated)
5/5 up-to-date (last run failed)
```

The first number is always how many hosts are on the current execution hash, out of every host the
plan targets; anything else is said in words after it. A host counts as up to date once a run has
applied the current playbook and inputs to it successfully, so `outdated` is what the next run has
left to do — for a `OneShot` plan, what stands between it and going quiet.

The last line is worth recognising: a `Recurring` run that fails on a host which already applied this
revision leaves nothing outdated, because the host still carries the hash its previous run gave it.
The drift count is genuinely `5/5` there, so the failure is named separately rather than left to be
inferred from a column that reads like good news. The `Ready` condition says how that run went
per-host.

## Conditions

`.status.conditions` carries `True`/`False` conditions. `Ready` and `Running` are also surfaced as
printer columns:

- **`Ready`** — the plan is in a healthy, settled state. Its `reason` says what it is reporting on,
  because two different things write it. Just after a run, `AllHostsSucceeded` /
  `SomeHostsDidNotSucceed` describe **that run**, counted over the hosts it targeted — in `OneShot`
  that is only the hosts that were out of date when it started. Between runs, `HostsUpToDate` /
  `HostsOutdated` describe **the whole plan**, counted over every eligible host. The two are worded
  differently on purpose: `n/m hosts completed successfully` is a statement about an execution,
  `n/m hosts on the current revision` about the plan's standing, and the second is not a claim that
  anything ran.
- **`Running`** — the operator has observed this run's own Job in a non-terminal state
  (`JobRunning`). It is set from an observation, not from Job creation, so it lags by a reconcile and
  covers a Job that is still scheduling, pulling its image or starting its pod. `Running=False` with
  reason `JobIdentityMismatch` means something that is not this run's Job holds the name the run
  recorded: the plan stays `Applying` and waits, renewing its host locks, because a contested name is
  never taken over or abandoned — the message names the Job. After a run finishes, `Running=False`
  carries no reason.
- **`Blocked`** — the run is due but waiting on a per-host lock held by another run; the condition
  message names the host and the run holding it. This one is not a column — read it with `kubectl
  describe` or `-o yaml`. It clears on its own once every lock the run needs is free. See
  [Host locks](./scheduling-and-modes.md#host-locks).
- **`WaitingForNodes`** — managed-SSH proxy pods are not `Ready` yet. The message names the pending
  Nodes. It clears when the proxies become Ready or their wait expires. See
  [NotReady nodes](./cluster-nodes.md#notready-nodes).

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

The plan's `.status` only reflects the **current** run. For a durable, per-run history, the
operator records a `Play` before creating the run's Job, in the plan's namespace and owned by the
plan (so they are removed when you delete it). Once a run launches, its `Play` corresponds to
exactly one Job; a run abandoned during preparation never creates one. Unlike a launched run's
Job, which Kubernetes reaps shortly after it finishes (`spec.ttlSecondsAfterFinished`), a `Play` keeps
the recap for as long as retention allows. Its spec preserves the plan UID, execution hash,
run ID, target inventory, preparation-input fingerprint, run number, attempt number, and schedule
slot, and
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
plays -o wide` adds the less-common counters (`rescued`, `skipped`, `ignored`), the run number and
the `Try` column — which try of its execution that run was, in the sense
[Retries](./scheduling-and-modes.md#retries) gives it. Each `Play`'s `.status` also carries the per-host recap and outcome plus `finishedAt`:

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
catch `Aborted`: the internal cleanup phase of a run that was given up before its Job existed.
Such a record is deleted once its resources are released, so a superseded run is never left behind
as a failed or unknown execution.

Which runs can be given up that way — and which are always left to finish — is one rule, covered
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
until its complete result, including the terminal phase and retry status, has been persisted on the
plan — so the limits can never discard the only surviving copy of a run's recap. Once acknowledged,
an old record whose deletion failed remains eligible for the next retention pass, including when a
history limit is zero. An `Aborted` record is deleted after
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

An idle `Recurring` plan does not create an empty Job when this happens. It reports **"plan
currently resolves to no hosts"** in `.status.summary` and continues to forecast
`.status.nextRun`. While it is not suspended, a previous run's `Succeeded` or `Failed` phase remains
visible; a plan that has never run is `Delayed`. If matching, authorized hosts return, the plan can
run on a later tick or in the current tick's grace window if it reconciles again before that window
closes.

### The plan's name is too long

The plan is `Failed` and its summary reads **"name is N characters; a PlaybookPlan name must be at
most 63 …"**. Applying such a plan is normally rejected outright; you only see this state on a
cluster that does not enforce CRD validation rules. Either way nothing is created for the plan.

The name is used as a label value on every object a run creates, and Kubernetes label values stop at
63 characters. An object's name cannot be changed, so recreate the plan under a shorter one — a
`kubectl edit` will not clear this.

### The plan's schedule or time zone is invalid

The operator cannot determine when the plan should run when its scheduling configuration is invalid.
Its summary reports one of these diagnostics:

- **`spec.timeZone "…" is not a recognized IANA time zone: …`** — use an IANA time-zone name such
  as `Europe/Berlin`, or remove `spec.timeZone` to use UTC.
- **`spec.schedule "…" is not a valid 5-field cron expression: …`** — provide exactly the minute,
  hour, day-of-month, month, and day-of-week fields; seconds and year fields are not supported.
- **`spec.schedule "…" has no future occurrence`** — the expression is syntactically valid but
  cannot produce another date; replace it with one that can.

The plan starts no new runs and clears `.status.nextRun` until the field is corrected. `Ready=False`
with reason `InvalidSchedulingConfiguration` carries the same diagnostic as the summary. An idle plan
without a run verdict moves to `Pending`, but a real `Succeeded` or `Failed` verdict from its latest
run remains visible rather than being hidden by the configuration error.

A run whose Job already exists is still allowed to finish, so its phase remains `Applying` until the
run completes. A run that has not created its Job is abandoned instead, following the same boundary
as any other spec edit; see [Editing a plan while a run is in
flight](./scheduling-and-modes.md#editing-a-plan-while-a-run-is-in-flight). Correcting the field clears
the readiness reason and restores the plan's host verdict or next scheduled time on the next
reconcile.

### The plan's inputs cannot be read

Two summaries report that the operator could not read what the plan says it should be running, and
so could not decide anything this tick:

- **"cannot resolve the plan's inventories: …"** — a referenced `ClusterInventory` or
  `StaticInventory` could not be read. `Referenced ClusterInventory "…" does not exist` means the
  reference is wrong or the inventory was deleted; anything else is an API error to retry.
- **"cannot read referenced Secrets: …"** — a Secret named by `spec.template.variables` or
  `spec.template.files` could not be read. `Referenced Secret "…" does not exist` means the reference
  is wrong or the Secret was deleted; anything else is an API error to retry.

Both reads are treated the same way, including for a run that is already in flight: a missing
resource is permanent and supersedes a run that has not launched, while anything else is
transient and holds it.

Neither starts a run and neither changes `.status.hostsStatus`, so the plan holds its previous
per-host results until the read succeeds; the operator retries every tick. The phase does go back to
`Pending` and `.status.nextRun` is cleared, so a plan in this state does not keep advertising the
last run's verdict or a scheduled slot it will not be able to act on. If a run was already in flight
when this happened it keeps its own phase, and it is *not* dropped for a transient error — see [The
plan is stuck in `Applying`](#the-plan-is-stuck-in-applying). When the inputs become readable again,
an idle `OneShot` plan whose hosts are still current restores `Succeeded` and its up-to-date summary;
it does not need a spec or Secret change to recover its visible status. While the inputs are
unavailable, `Ready=False` with reason `InputsUnavailable` makes that temporary uncertainty explicit.

That reason is retired on the first tick that reads the inputs cleanly, in every mode, and `Ready`
goes back to describing the hosts: `True`/`HostsUpToDate` when every eligible host is at the current
revision, `False`/`HostsOutdated` counting how many are, with the message `n/m hosts on the current
revision`. That is deliberately not the wording a finished run uses — nothing ran, so it does not
claim anything completed, and it covers the whole plan rather than the subset one run targeted. A
plan that had not yet run when the outage started is left without a `Ready` condition, as it was
before. This matters most for `Recurring` plans, which have no idle verdict to restore and would
otherwise advertise a resolved outage in their `READY` column until their next slot finished.

### A plan is not starting and its `Blocked` condition is `True`

Another run is holding a lock on a host this plan targets, so the plan is waiting its turn — host
locks are cluster-wide, and a Node is applied to by one run at a time (see
[Host locks](./scheduling-and-modes.md#host-locks)). `kubectl describe playbookplan <name>` shows the
host and the run holding it, and the operator logs a matching warning. This is normal when two plans
share hosts: the run proceeds once the other finishes. If it never clears, look at the run named as
the holder — a plan that runs very often (a `Recurring` plan on a tight schedule, or one retrying a
failed run) can keep an overlapping plan waiting for a long time.

### The plan is stuck in `Applying`

A plan stays `Applying` for as long as a run is in flight, which for a long playbook is simply
normal — `.status.summary` then reads **"applying run …"**, naming the run, and the `Blocked` and
`WaitingForNodes` conditions say whether it is waiting on a host lock or on proxy pods rather than
executing.

If it stays there with nothing progressing, `.status.summary` says which of the following it is
instead, and `.status.activeRun` names the run it is waiting on:

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
  name must also be the one recorded by the `Play`, including the trailing run number, which is
  where the operator reads the run from. Any mismatch confirms that the Job is foreign. A Job that
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
- **"could not prepare run …: Pod/Secret … already exists but is not this run's managed-ssh proxy
  for host …"** — the operator found an object at a derived proxy-resource name in the operator
  namespace, but could not prove that it belongs to this run and host. It refuses to treat the object
  as this run's proxy because a managed-SSH proxy grants node-root access, keeps the run's host locks,
  and retries the check.

  This can mean an object was planted or edited in the operator namespace. It can also mean two Node
  names produced the same shortened resource-name segment, which requires a deliberately constructed
  collision rather than an ordinary hash accident. Inspect the exact Pod or Secret named in the
  message. Its run ID, execution hash and component labels and its full target-host annotation must
  identify the active run and host; the Pod must also select that host's Node. Delete the object only
  after confirming that it is foreign and that its owner considers deletion safe. For a Node-name
  collision, change the inventory selection so the colliding Nodes are not targeted by the same run.
- **"could not complete run …: …"** — the run's Job reached a terminal state, but the operator could
  not finish handling it: releasing its proxy pods or host locks, writing the recap onto its `Play`,
  or folding that result into the plan. The rest of the message is the underlying error, and every
  step is idempotent, so the operator retries the whole sequence every tick and this clears on its
  own once the underlying problem does. Until then the run's proxy pods may still be up — worth
  looking at if the message persists, since these are node-root pods. The run's `Play` is deliberately
  kept meanwhile: it is the handle the retry works from, so do not delete it to unstick the plan.
- **"run recovery failed: …"** — the operator could not resume the run after a restart. The rest of
  the message is the underlying error; the operator retries every tick. If the message is
  **"more than one Play claims to be this plan's active run"**, something outside the operator
  created a second run record: a plan only ever has one run in flight, and the operator refuses to
  guess which one is real rather than orphan the other's proxy pods. Look at
  `kubectl get plays -n <ns> -l ansible.cloudbending.dev/playbookplan=<plan>`, work out which record
  the operator wrote, and delete the stray one. The host locks of both are kept alive meanwhile, so
  no other plan can start on those hosts while you do.
- **"run recovery paused: …"** — the operator needs something it cannot currently read to decide
  what to do with the run: an inventory, `NodeAccessPolicy` or referenced Secret lookup that is
  failing for a reason that may clear on its own, such as an API error or a lost connection. The
  run is deliberately *held*, not dropped: its host locks keep being renewed so no other plan can
  start on those hosts while the question is open, and the operator retries every tick. Unlike the
  messages above, this one can persist indefinitely if the underlying read never succeeds — the rest
  of the message is the error to fix. A read that fails because the resource is simply *gone* is not
  this case; see the next message.
- **"aborted the run because its desired inputs cannot be resolved: …"** — the same lookup failed in
  a way that cannot be transient: a referenced `ClusterInventory`/`StaticInventory` or a referenced
  variables/files `Secret` no longer exists, or an inventory group sets a variable the operator
  manages. There is no executable desired state left, so the run was released and deleted; fix
  the reference and a fresh run starts. Giving the run up rather than holding it also frees
  its host locks — a run held indefinitely blocks every other plan targeting those hosts, not
  just this one. If its Job had already been created it is adopted and allowed to finish instead,
  reported as **"adopted the started run; the desired inputs cannot be resolved: …"**.
- **"aborted the run: host '…' is now locked by …"** — while the run was still being set up,
  another run was *observed* holding one of its host locks (its own lease lapsed during an operator
  outage and the other run took it over). Rather than run two playbooks against the same host, it was
  released and deleted; it starts again once the host is free.
- **"could not confirm the lock on host '…'; retrying"** — the same check, but inconclusive: the
  operator raced another writer on that Lease and cannot say who holds it. Nothing was seen taking
  the lock over, so the run is deliberately *kept* and the question is asked again a second
  later. If this persists, something outside the operator is writing to its Leases.
- **"aborted the run: its nodes are no longer granted to this namespace"** — the run's
  `NodeAccessPolicy` grant was withdrawn while it was being set up, so it was abandoned before its
  playbook could reach those nodes. Its locks and proxy pods are released and the plan re-evaluates.
  See [Node access policies](../cluster-operators/node-access-policies.md).
- **"aborted the run: it may no longer start (the desired revision changed or it missed its schedule
  window)"** and **"aborted the run: it may no longer launch and its Job was never created"** — the
  ordinary supersede path: the plan was edited (or its resolved nodes changed) while a run was
  still preparing. The second wording is the same decision for a run that had already committed
  to launching, once the API server confirmed its Job was never created. See [Editing a plan while a
  run is in flight](./scheduling-and-modes.md#editing-a-plan-while-a-run-is-in-flight).
- **"aborted the run: the plan was suspended before its Job was created"** — `spec.suspend` was set
  while a run was still preparing, so it was dropped rather than left to launch whenever it
  became able to. Unlike the other "aborted the run…" messages this one is a *resting* state: the
  plan stays idle until you resume it. It returns to `Pending` if this was the execution's first
  attempt, or to the preceding `Failed` verdict if an unlaunched retry was dropped. See [Suspending
  a plan](./scheduling-and-modes.md#suspending-a-plan).
- **"released the abandoned run …"** — cleanup of a run abandoned by an earlier tick has now
  finished. Only seen after a "could not release the abandoned run …" below, or after a restart
  interrupted a teardown; the plan re-evaluates immediately.
- **"recorded a finished run; another run is still in flight"** — after an outage, more than one
  finished result can be waiting to be written to the plan. The operator applies them one tick at a
  time, oldest first, and says so rather than reporting the plan finished while a later run is
  still going. It clears on its own.
- **"could not release the abandoned run …"** — one of the "aborted the run…" cases above got as
  far as deciding to give the run up, but could not finish tearing it down: a proxy pod, Secret,
  NetworkPolicy or Lease would not delete, or its run record could not be removed afterwards. The
  rest of the message is the underlying error. The run's record is deliberately kept as the
  handle for retrying that cleanup, and the operator retries every tick, so this clears on its own
  once the underlying problem does. Until then the run's proxy pods may still be up — worth looking
  at if the message persists, since these are node-root pods. This is the one message here that can
  also appear while the phase reads `Pending`, if the teardown got as far as clearing the run before
  failing.

  Fixing the reported permission, admission, finalizer or API problem is safest: cleanup is
  idempotent, so the operator resumes it automatically. If that is impossible, a cluster
  administrator can clean up the exact run manually. Read its identity first:

  ```sh
  PLAN_NAMESPACE=my-team
  PLAN=my-plan
  PLAY=apply-my-plan-abcde-1
  OPERATOR_NAMESPACE=ansible-operator
  RUN_ID=$(kubectl get play "$PLAY" -n "$PLAN_NAMESPACE" -o jsonpath='{.spec.runId}')
  HASH=$(kubectl get play "$PLAY" -n "$PLAN_NAMESPACE" -o jsonpath='{.spec.executionHash}')
  SELECTOR="ansible.cloudbending.dev/hash=$HASH,ansible.cloudbending.dev/run-id=$RUN_ID"
  ```

  Delete only resources carrying both run labels. The first two commands remove the node-root
  proxy infrastructure in the operator namespace; the third removes the plan-namespace credential
  and egress policy:

  ```sh
  kubectl delete pods -n "$OPERATOR_NAMESPACE" \
    -l "$SELECTOR,ansible.cloudbending.dev/target-host"
  kubectl delete secrets,networkpolicies -n "$OPERATOR_NAMESPACE" -l "$SELECTOR"
  kubectl delete secrets,networkpolicies -n "$PLAN_NAMESPACE" -l "$SELECTOR"
  ```

  Finally inspect Leases in the operator namespace and delete only those whose
  `.spec.holderIdentity` is exactly `$PLAN_NAMESPACE/$PLAN/$RUN_ID`:

  ```sh
  kubectl get leases -n "$OPERATOR_NAMESPACE" \
    -o custom-columns=NAME:.metadata.name,HOLDER:.spec.holderIdentity
  kubectl delete lease -n "$OPERATOR_NAMESPACE" <matching-lease-name> [...]
  ```

  Re-read the holder identity of each Lease immediately before deleting it, and delete it only while
  it still names this run. A host lock is the one thing another plan can take over between the two
  commands: a lapsed Lease is acquired by whichever run wants that host next, and it keeps the same
  Lease name. If the holder no longer matches, **stop** — the host now belongs to a live run, and
  deleting its Lease hands the same host to a third run while Ansible is on it.

  Once those resources are gone, the operator can delete the `Aborted` Play itself on its next
  retry. Delete the Play by hand only after verifying the cleanup; deleting the recovery handle
  first can leave privileged resources with nothing identifying them for later cleanup.

With the sole exception of the `suspend` one, every "aborted the run…" message above is a transient
state rather than a resting one: the run is gone and the plan re-evaluates immediately, so if the
plan stays `Applying` on one of them the *next* tick has usually already replaced it with something
else. A run that is merely pausing *before* it launches reports that through a condition instead:
`Blocked` for a contended host lock, or `WaitingForNodes` for proxy pods that are not `Ready` yet.

### The plan is stuck in `Terminating`

A deleted plan is held by the `ansible.cloudbending.dev/run-cleanup` finalizer until the operator has
cancelled its run and released the resources that outlive the plan's namespace — its managed-ssh
proxy pods and its host Leases. Normally that takes a few seconds. It lasts longer when:

- **the run's pod will not stop.** The operator waits for it deliberately, renewing the run's host
  locks meanwhile, so that no other plan starts against a host while Ansible may still be on it. The
  operator log names the run it is waiting on; look at the Job's pod (`kubectl get pods -n
  <plan-namespace> -l ansible.cloudbending.dev/run-id=<runId>`) and at anything blocking its
  termination, such as a long `terminationGracePeriod` or a stuck finalizer on the pod itself.
- **the node running the run's pod is unreachable.** The pod's phase then reads `Unknown`, which
  says the node stopped reporting, not that the playbook stopped — a partitioned node keeps running
  its containers, and the hosts the run is applying to are usually other nodes entirely. The
  operator therefore keeps waiting and keeps renewing the run's host locks. Recovering the node
  resolves it; so does removing the `Node` object, after which Kubernetes deletes the pods bound to
  it and the teardown finishes on its own.
- **the operator is not running.** Nothing releases the run until it comes back; the plan waits
  rather than leaking. Restore the operator and the deletion completes on its own.
- **the plan's namespace was un-enrolled while the run was in flight.** The operator can then neither
  release the run nor remove its own finalizer. Re-enrol the namespace and it finishes the teardown;
  see [Deployment → enrolled namespaces](../cluster-operators/deployment.md#enrolled-namespaces).

Removing the finalizer by hand ends the wait but strands the run's proxy pods and host Leases. Before
doing it, capture the run's identity — the plan's `Play` records and its Job are owned by the plan
and are deleted with it, and they are what the manual cleanup procedure reads those values from:

```sh
PLAN_NAMESPACE=my-team
PLAN=my-plan

kubectl get playbookplan "$PLAN" -n "$PLAN_NAMESPACE" -o jsonpath='{.status.activeRun}'
```

Keep the `runId`, `executionHash` and `jobName` it prints, together with `$PLAN` and
`$PLAN_NAMESPACE` — the run's Leases are held under `$PLAN_NAMESPACE/$PLAN/<runId>`. With those in
hand, the manual cleanup procedure under [The plan is stuck in
`Applying`](#the-plan-is-stuck-in-applying) applies to a run whose plan is already gone: skip its
first block, which reads the same values from a `Play` that no longer exists, and set `RUN_ID`, `HASH`
and `SELECTOR` from what you captured.

That procedure is written for a run the operator had already given up, whose playbook is therefore no
longer executing. Here it may still be — a pod that will not stop is the first reason to land in this
section at all — so stop the run yourself before running any of it, in the order the operator itself
uses. Deleting the plan reaps the Job too, but with the deleting client's propagation policy, which
does not order the Job's removal after its pods; cancel it explicitly and wait:

```sh
JOB=<jobName>
RUN_ID=<runId>

kubectl delete job "$JOB" -n "$PLAN_NAMESPACE" --cascade=foreground --ignore-not-found
kubectl get job "$JOB" -n "$PLAN_NAMESPACE"
kubectl get pods -n "$PLAN_NAMESPACE" -l "ansible.cloudbending.dev/run-id=$RUN_ID"
```

Both reads must come back empty before you delete anything else. Foreground deletion keeps the Job
until garbage collection has removed every pod of it, so a Job that is gone is proof that no pod of it
survives; the pods are still listed afterwards because a pod outlives its Job object while it
terminates, and it is the pod that holds the SSH session. Releasing the run's Leases before that
hands its hosts to another plan while Ansible is still talking to them — which is the single outcome
the whole locking design exists to prevent, and the reason the operator waits here rather than
proceeding.

If the plan is already gone and nothing was captured, use [orphaned run resources with no
plan](#orphaned-run-resources-with-no-plan) below.

### Orphaned run resources with no plan

Proxy pods and host Leases in the operator's namespace outlive a plan that was force-deleted, and
they carry no plan name — only an execution hash, a run ID and a target host. They can still be
identified without the plan, because a live run is always named by one of two records: its `Play`,
written *before* it takes any host lock or builds any proxy infrastructure and removed by the operator
only after that infrastructure has been released, and its plan's `status.activeRun`, which mirrors the
same run for as long as the plan holds it.

Both have to be checked, because neither alone is proof. A `Play` can be deleted out from under a
live run — by hand, or by anything else with access to it — and the operator supports that: it
releases the run from `status.activeRun` instead, and reports its hosts as `Unknown`. Until it gets
to that, and for the whole of any operator outage, the run is live, its Leases and proxy pods are
live, and no `Play` names it. A run that appears in *neither* record is the orphan this section is
about.

The Node a proxy serves is read from its `ansible.cloudbending.dev/target-host` **annotation**, which
always spells the Node name out in full. The label of the same name is the selectable form and is
shortened — truncated, with a hash appended — for a Node whose name does not fit in a label value's
63 characters, as is the pod's own name.

List what the operator namespace holds and the run IDs that are still accounted for:

```sh
OPERATOR_NAMESPACE=ansible-operator

kubectl get pods -n "$OPERATOR_NAMESPACE" \
  -l ansible.cloudbending.dev/component=managed-ssh-proxy \
  -o custom-columns='NAME:.metadata.name,RUN:.metadata.labels.ansible\.cloudbending\.dev/run-id,HASH:.metadata.labels.ansible\.cloudbending\.dev/hash,NODE:.metadata.annotations.ansible\.cloudbending\.dev/target-host'

kubectl get leases -n "$OPERATOR_NAMESPACE" \
  -o custom-columns=NAME:.metadata.name,HOLDER:.spec.holderIdentity

kubectl get plays -A \
  -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,RUN:.spec.runId

kubectl get playbookplans -A \
  -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,RUN:.status.activeRun.runId
```

Compare them run ID by run ID, against both of the last two listings. A Lease's holder identity is
`<plan namespace>/<plan>/<run ID>`, so its third field is what to match on:

- **the run ID appears in a `Play` or in a plan's `activeRun`** — that record is the run's recovery
  handle and the operator may still be working on it. Do not delete anything by hand; go to that
  plan and follow the per-run procedure, which is written for exactly that case. A run named only by
  an `activeRun` is a live run whose `Play` was deleted; the operator releases it from that mirror on
  its own, and a plan stuck in `Terminating` is the section above, not this one.
- **the run ID appears in neither** — its plan is gone, so nothing will ever come back for these
  resources. Delete them with the commands under [The plan is stuck in
  `Applying`](#the-plan-is-stuck-in-applying), using that run ID and the hash from the pod's label.
  Only the operator-namespace commands apply: the run's plan-namespace resources were owned by the
  plan and Kubernetes removed them with it. If you need the plan's name and namespace anyway — to
  record what was cleaned up, or to match a Lease to a pod — the Lease's holder identity is the last
  place they still appear.

  Confirm first that the run's pods are gone, in the namespace the Lease's holder identity names:
  `kubectl get pods -n <plan namespace> -l ansible.cloudbending.dev/run-id=<run ID>`. The run's Job
  was reaped with its plan, but under background propagation — the default — the Job object is removed
  at once and its pods are deleted afterwards, so a Job that is already gone says nothing about
  whether Ansible has stopped. If that namespace was deleted along with the plan, the pods went with
  it and there is nothing left to wait for.

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

If *every* host of one run shows `Unknown` at once, check these causes first:

- **The managed-SSH preflight init container could not start.** On a plan targeting cluster Nodes,
  `managed-ssh-preflight` runs `python3` from the plan's execution image before Ansible starts. A
  fresh image without `python3` on `PATH` therefore produces no recap and reports every host as
  `Unknown`. Inspect the init container's logs and status:

  ```sh
  kubectl logs job/<job-name> -c managed-ssh-preflight
  kubectl get pod <pod-name> -o jsonpath='{.status.initContainerStatuses}'
  ```

  See [`python3` must be on `PATH`](./playbook-plans.md#python3-must-be-on-path) for the image
  requirement and a local verification command.
- **The run's `Play` was deleted while the run was still live.** That record is the only thing the
  run can be recovered from, so the operator releases the run's locks and proxy pods and reports
  the whole run as unknown rather than leaving the plan stuck. The next run reports these hosts
  normally.

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

### A `OneShot` plan is `Failed` and stops trying

It has spent its [attempt budget](./scheduling-and-modes.md#retries): `.status.retryCount` has
reached `spec.maxAttempts` (3 by default), so the plan holds its `Failed` result instead of applying
a playbook its hosts have already refused that many times. Fix the cause and edit the playbook or a
referenced Secret — the new execution hash starts a fresh budget — or raise `maxAttempts` to let it
try again with the inputs unchanged. The failed runs are still in the plan's
[run history](#run-history), which is where the recap of each attempt is.
