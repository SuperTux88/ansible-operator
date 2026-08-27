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

## Suspending a plan

Set `spec.suspend: true` to stop the operator starting new runs, the same idea as a CronJob's
`.spec.suspend`. It is a pause switch, not a delete:

- A run **already in progress** is left to finish — suspending never kills a running Job.
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
  plan resets to `Pending`, clears its retry bookkeeping, and every host becomes out of date again.

This is what makes `OneShot` idempotent and cheap: editing an unrelated field does not re-run
everything, but a real change to the playbook or its inputs does. The current hash is visible as
`.status.currentHash` and in the `Current hash` printer column.

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
host and the run holding it, and the operator logs a warning. The plan's phase stays `Scheduled` (or
`Pending`) meanwhile: being blocked is a temporary wait, not a failure, and the run proceeds on its
own as soon as the lock is free.

A crashed operator's locks expire on their own after a short period, so a host is never left locked
indefinitely.

## Cleaning up finished Jobs

`spec.ttlSecondsAfterFinished` controls how long a finished run's Job and its pod linger before
Kubernetes' TTL controller reaps them (values below 60 seconds are raised to 60). Set it higher if
you want more time to inspect a finished pod, lower to reclaim resources sooner. The recap the
operator needs is captured from the pod's termination message at completion, so reaping the pod does
not lose your `.status` results.
