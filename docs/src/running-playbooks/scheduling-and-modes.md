# Scheduling and execution modes

Two independent things decide *when* a plan runs and *what* runs:

- the **schedule** (and time zone) decides at which wall-clock times a run may fire;
- the **execution mode** plus **drift detection** decide which hosts actually execute when a run does
  fire.

## Schedule

`spec.schedule` is a standard **5-field cron** expression (`minute hour day-of-month month
day-of-week`). `spec.timeZone` is the IANA time zone it is evaluated in; if omitted, **UTC** is used.
The granularity is minutes, not seconds.

The operator evaluates the schedule on its own reconcile cycle rather than exactly on the tick, so a
run starts within a short window *after* each scheduled time. `spec.startingDeadlineSeconds` sets how
wide that window is: if the run has not started within this many seconds of the tick — because the
operator was busy or restarting — that tick is skipped and the run waits for the next one. It
defaults to **30** seconds. Raise it for a plan that must not miss a tick even if the operator is
briefly down at the scheduled time. This is the same idea as a CronJob's `.spec.startingDeadlineSeconds`.

```yaml
spec:
  schedule: "0 3 * * *"          # 03:00 every day
  timeZone: Europe/Berlin        # ...in Berlin local time (honours DST)
  startingDeadlineSeconds: 300   # still fire if the operator catches up within 5 minutes
```

**Omitting `schedule`** means "eligible to run as soon as possible", not "never": the plan is not
gated on a clock and runs when its hosts are out of date. Use an explicit schedule when you want runs
pinned to a maintenance window.

The plan's `.status.nextRun` shows the next computed fire time, and the `Next run` printer column
surfaces it in `kubectl get playbookplan`.

### One tick, one run per revision

Because a run may start anywhere inside that window, the operator has to remember that the window has
already been used — otherwise a run finishing inside its own window would immediately re-trigger
itself. `.status.lastTriggeredRun` records the tick a run was last started for, and a tick that
matches it is skipped.

That memory is per revision, not per window: any change to the [execution hash](#drift-detection)
clears `lastTriggeredRun`, so an edit made moments after a run started takes effect right away rather
than waiting for the next tick. Reverting to an earlier revision is a change like any other and runs
again too.

## Suspending a plan

Set `spec.suspend: true` to stop the operator starting new runs, the same idea as a CronJob's
`.spec.suspend`. It is a pause switch, not a delete:

- A run whose **Job already exists** is left to finish — suspending never kills a running Job.
- An attempt that has **not created its Job yet** — one still waiting for its host locks, or still
  bringing up its proxy pods — is dropped instead: nothing irrevocable exists for it, so pausing the
  plan stops it rather than letting it launch whenever it becomes able to. It is cleaned up and
  deleted the same way an attempt superseded by an edit is, and a fresh attempt starts once you
  resume. See [Editing a plan while a run is in
  flight](#editing-a-plan-while-a-run-is-in-flight).
- No **new** run is started while suspended, in any mode: a `Recurring` plan skips its schedule
  ticks, and a `OneShot` plan holds off even when hosts are out of date.
- The `Suspended` printer column reads `true` and `.status.nextRun` is cleared — there is no next run
  while paused. The plan's phase keeps showing its underlying state (e.g. `Scheduled` or
  `Succeeded`); the column, not the phase, is what tells you it is paused.

Clear the flag (`spec.suspend: false`, or remove it) to resume; a `Recurring` plan picks up again at
its next scheduled tick. Suspending does not pause drift detection — editing the playbook or a
referenced Secret while suspended still updates the current hash, so the run that eventually resumes
reflects the latest inputs.

## Execution modes

`spec.mode` is one of:

### `OneShot` (default)

Converge to a goal state and then stop. Only **out-of-date** hosts run; once every host has succeeded
on the current playbook and inputs, the plan settles into `Succeeded` (or `Failed` if some host could
not be brought current) and stops — it does **not** keep re-running on the schedule. It wakes again
only when the inputs change (see drift detection below). Good for "make it so": apply a configuration
or a one-time migration and confirm every host got it.

### `Recurring`

Re-apply on **every** schedule tick. *All* hosts run each time, regardless of whether they ran
successfully last time, and the plan reschedules itself back to `Scheduled` for the next tick. Good
for periodic enforcement or inherently repeating work: nightly package upgrades, drift correction,
health tasks. A `Recurring` plan needs a `schedule`.

## Drift detection

To decide which hosts are out of date, the operator computes an **execution hash** over the playbook
text **plus the contents of every referenced Secret** (variables and files). The hash is
order-insensitive, so reordering inputs does not count as a change, and it excludes the internally
rendered workspace, whose content (e.g. proxy pod IPs) legitimately changes every run.

- Each host records the hash it **last succeeded on** (`.status.hostsStatus.<host>.lastAppliedHash`).
- A host whose last-applied hash equals the current hash is **current** and is skipped (in
  `OneShot`).
- When you edit the playbook, or change a referenced variables/files Secret, the hash changes: the
  desired hash, retry bookkeeping and [consumed schedule slot](#one-tick-one-run-per-revision) update
  immediately. An in-flight attempt keeps its own hash, target inventory, retry number, and schedule
  slot in an immutable `Play`, so the edit does not disturb it — see [Editing a plan while a run is in
  flight](#editing-a-plan-while-a-run-is-in-flight).

This is what makes `OneShot` idempotent and cheap: editing an unrelated field does not re-run
everything, but a real change to the playbook or its inputs does. The current hash is visible as
`.status.currentHash` and in the `Current hash` printer column.

## Editing a plan while a run is in flight

You can edit a plan at any time; you never have to wait for a run to finish. What happens to the run
already in progress depends on whether its Job has been created yet. That is never assumed: the
operator asks the API server directly, and asks again immediately before giving up on an attempt, so
a Job that only became visible in between is still found and adopted rather than having its
infrastructure torn down underneath it.

**A run whose Job exists keeps going.** It finishes the playbook it started, against the hosts it
started with, and its results are recorded against the revision it actually ran. The operator does not
kill it, swap its playbook underneath it, or attribute its recap to your new revision. Your edit takes
effect on the next run.

**A run whose Job does not exist yet is abandoned.** An attempt that is still waiting for host locks,
still bringing up its proxy pods, or committed but not yet launched is dropped in favour of the new
revision: its locks are released and any proxy infrastructure it had started building is cleaned up.
It is deleted rather than reported as a failed or unknown execution, and it is never retried — there
is no point applying a revision you have already replaced. A fresh attempt then starts for the plan as
it now reads.

This second case is triggered by more than the execution hash. An unlaunched attempt is abandoned
whenever *any* part of the plan spec changes — the image, tolerations, verbosity, inventory
references — or when the set of nodes the plan resolves to changes, for instance because a node was
relabelled or a `NodeAccessPolicy` was narrowed. The hash decides which hosts are out of date; this
check decides whether an attempt still matches the plan it was prepared for, and it is deliberately
the stricter of the two. Setting `spec.suspend: true` has the same effect, for the same reason:
nothing irrevocable exists for an unlaunched attempt, so a paused plan drops it instead of launching
it later.

One trigger is narrower than the rest. An attempt that is still waiting for its **host locks** is
also dropped if it misses its schedule window, because it has yet to consume the slot it was started
for. That gate lifts as soon as the locks are held: bringing up proxy pods routinely takes longer
than `startingDeadlineSeconds`, so keeping it would leave a scheduled plan unable to launch at all.

An absent-Job attempt is also abandoned when something it references no longer exists — one of its
inventories, or a Secret named by `spec.template.variables`/`files` — or when an inventory group
contains an operator-reserved connection variable: there is no executable desired state left to
resume it against. An attempt that had already committed to launching is re-checked first, and if its
Job does exist by then it is adopted and allowed to finish like any other started run — a broken
reference belongs to the *next* revision, not to a run that is already under way. A transient failure
reading otherwise valid inventory, policy or Secret data abandons nothing at all; it only pauses
recovery, with the attempt's host locks kept alive, rather than launching from incomplete input.

The distinction matters because holding an attempt is not free: its host locks keep being renewed for
as long as it is held, so an attempt waiting on something that is never coming back would block every
other plan targeting those hosts indefinitely. A missing reference is therefore resolved rather than
waited on.

The practical consequence: repeatedly editing a plan while its runs are still starting up can keep
starting fresh attempts. That is intentional — each abandoned attempt is cleaned up and costs nothing
but the setup time — but if you are making a series of edits, `spec.suspend` is the tidier way to
batch them.

## Retries and attempt numbers

If a run's Job needs to be retried, the operator numbers successive Jobs
(`apply-<plan>-<id>-<n>`) rather than colliding on one name. Attempt numbers are reserved across
the plan as a whole, not per execution hash: each is one past every Job and retained `Play` record
that still claims a number. The hash suffix can be shared by different revisions, so numbers may
skip ahead and do not restart at 1 when you edit the plan. You generally do not interact with this;
it is why you may see more than one Job object, and more than one `Play`, for the same run, and why
`.status.retryCount` is not a count of how often the current revision has been tried.

A Job's name is capped at 63 characters by Kubernetes, so the plan-name portion is shortened to fit.
The rest of the name — `apply-`, the id and the attempt number — takes 19 characters at a
single-digit attempt, leaving 44: a plan named 45 characters or more is shortened, and one more
character goes each time the attempt number gains a digit. The `Play` shares the shortened name, so
the two always match.

## Host locks

The operator applies at most one playbook to a given host at a time, across the whole cluster. Before
a run starts it takes a short-lived lock — a Kubernetes `Lease` in the operator's namespace — on every
host the run targets, and releases them when the run finishes. Locks are keyed by host and shared by
every plan, so two plans that target the same Node cannot run against it at once, even when they live
in different namespaces.

Acquisition is all-or-nothing: a run starts only once it holds the lock for **every** host it targets.
If another run holds any of them, the plan waits and retries rather than running against part of its
inventory. Plans whose hosts overlap therefore take turns — one run finishes and releases its locks,
then the next acquires them. Plans over completely separate hosts never block each other.

While a plan is waiting on a lock held by another run, its
[`Blocked` condition](./results-and-troubleshooting.md#conditions) is `True`, its `.status` names the
host and the run holding it, and the operator logs a warning. The plan is `Applying` because its
recorded attempt is active, while the `Running` condition only becomes `True` once a reconcile has
*observed* the run's Job executing — so it lags Job creation by one tick, and on a plan's first run
it is not set at all until then. Being blocked is a temporary wait, not a failure, and the run
proceeds on its own as soon as the lock is free.

A crashed operator's locks expire on their own after a short period, so a host is never left locked
indefinitely.

## Cleaning up finished Jobs

`spec.ttlSecondsAfterFinished` controls how long a finished run's Job and its pod linger before
Kubernetes' TTL controller reaps them (values below 60 seconds are raised to 60). Set it higher if
you want more time to inspect a finished pod, lower to reclaim resources sooner. The recap the
operator needs is captured from the pod's termination message at completion, so reaping the pod does
not lose your `.status` results.
