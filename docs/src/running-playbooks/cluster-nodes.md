# Targeting cluster nodes

A `ClusterInventory` builds host groups **from your cluster's own Nodes**, matched by Node labels,
and reaches them over *managed SSH* — the operator's agentless, node-root access path. Use it to run
playbooks against the machines your cluster runs on: OS patching, kernel and k3s upgrades,
node-level configuration, and the like.

> **Managed SSH is node-root.** A managed-SSH session is `root` on the target Node, which is why
> access to it is gated. Which Nodes your namespace may reach is capped by a cluster-admin-authored
> `NodeAccessPolicy`; if a `ClusterInventory` resolves to **zero** hosts even though Nodes match your
> selector, no policy grants your namespace those Nodes. See
> [Node access policies](../cluster-operators/node-access-policies.md).

## Defining host groups

Each entry under `spec.hosts` is a group: a `name` plus a Node **label selector**. A Node that
matches lands in that group, and the group name becomes an Ansible group your playbook can target. A
group may use either selector form, following Kubernetes' label-selector semantics:

- **`matchLabels`** — an exact-match map; a Node must carry every listed label and value.
- **`matchExpressions`** — a list of `{ key, operator, values }` terms with operators `In`, `NotIn`,
  `Exists`, `DoesNotExist`, and the ordered `Gt`, `Ge`, `Lt`, `Le` described under
  [Comparing versions](#comparing-versions).

```yaml
apiVersion: ansible.cloudbending.dev/v1beta1
kind: ClusterInventory
metadata:
  name: cluster-nodes
spec:
  hosts:
    - name: controlplanes
      matchLabels:
        kubernetes.io/os: linux
        node-role.kubernetes.io/control-plane: "true"
    - name: workers
      matchExpressions:
        - { key: kubernetes.io/os, operator: In, values: [linux] }
        - { key: node-role.kubernetes.io/control-plane, operator: DoesNotExist }
```

The controller watches Nodes and keeps `.status.resolvedHosts` and `.status.hostCount` up to date as
Nodes are labelled, added, or removed, so `kubectl get clusterinventory` shows how many Nodes
currently match. `hostCount` counts each Node once even when several of the inventory's groups match
it — the same way a plan's `n/m hosts` summary does, since one Node is one host to a run whatever it
is grouped under. `resolvedHosts` still lists it under every group it belongs to; that is what makes
the group names usable in a playbook's `hosts:`.

`.status.observedGeneration` records the `metadata.generation` those hosts were resolved from. A plan
reads the published `resolvedHosts` rather than evaluating the selectors itself, so until the
controller has caught up with an edit they still describe the *previous* spec — and a plan that
started a run in that window would target the Nodes the edit replaced. Plans therefore start no new
run from an inventory whose `observedGeneration` is behind its `metadata.generation`, and say so in
their summary; the catching-up status write wakes them, normally within seconds. This matters most
for a single `helm upgrade` that changes an inventory and a plan together, since Helm applies both in
one pass and waits for no status.

## Comparing versions

`Gt`, `Ge`, `Lt` and `Le` order a Node's label value against the term's **single** value as a
version — "at least 1.4.0", rather than one exact string you have to edit at every bump:

```yaml
matchExpressions:
  - { key: platform.plan.ansible.cloudbending.dev/containerd-config, operator: Ge, values: ["1.4.0"] }
```

Both sides are read leniently and then ordered by [SemVer](https://semver.org): a leading `v` is
optional, missing components count as zero (`1.4` is `1.4.0`), and build metadata after `+` or `_` is
ignored. Two consequences to keep in mind:

- **A pre-release sorts *before* its release.** `Ge 1.4.0` does not match `1.4.0-rc.1`, which is
  usually what you want from a release candidate.
- **A short value is filled up with zeros, including yours.** `Ge 2` is `Ge 2.0.0`, so it matches
  `2.1.1` and every other 2.x — you do not have to spell out `2.0.0`. It only reads as "the 2.x
  series" in that direction, though: `Le 2` is `Le 2.0.0` and therefore *excludes* `2.1.1`. To cap a
  series, say `Lt 3`.
- **A range is two terms.** Each term takes one value, and all terms in a group must hold, so
  `Ge 1.4.0` plus `Lt 2.0.0` is how you express "1.x from 1.4 on".

This is not the same as Kubernetes' own `Gt`/`Lt`, which exist only for node affinity and parse
**both** sides as integers — a dotted version never matches one. Comparing as plain strings would be
worse than useless here, since it sorts `1.10.0` before `1.9.0`. An integer is simply a
one-component version to these operators, so anything Kubernetes' versions of them accept compares
exactly as it would there.

Anything the comparison cannot answer **does not match**: a Node without that label, a label value
or term value that is not a version (`latest`, say), or a term listing zero or several values. A
selector you expected to match nothing but Nodes that are ready therefore errs towards *not*
running, never towards running somewhere it should not.

## Depending on another plan

A plan that declares [`spec.provides`](./playbook-plans.md#declaring-what-a-plan-provides) labels
every Node it has converged. Select on that label and your inventory resolves to "the Nodes where
that plan has finished", growing by itself as the other plan works through its hosts:

```yaml
kind: ClusterInventory
metadata:
  name: workers-with-containerd
spec:
  hosts:
    - name: workers
      matchLabels:
        node-role.kubernetes.io/worker: ""
      matchExpressions:
        - key: platform.plan.ansible.cloudbending.dev/containerd-config
          operator: Exists
```

`Exists` accepts whatever version the providing plan has applied. To require a particular one, use
`In` for an exact value or `Ge` for "this version or newer" — see
[Comparing versions](#comparing-versions):

```yaml
      matchExpressions:
        - key: platform.plan.ansible.cloudbending.dev/containerd-config
          operator: Ge
          values: ["1.4.0"]
```

A host that is not ready yet is simply **not in the run** — it costs no attempt, holds no Lease and
starts no proxy pod, which is exactly why this is expressed as a host set rather than as a wait
inside the playbook. When the providing plan succeeds on another Node, that Node's label reaches
this inventory's `resolvedHosts` within seconds and the dependent plan is woken.

The label is cluster-wide, so the providing plan may live in **another namespace** — the key names
it, which is also why every key is visible to anyone who can read Nodes.

Two things to get right when you copy an existing inventory to add a dependency:

- **Keep the group `name`.** It becomes the Ansible group, so a copy that keeps `workers` lets the
  same playbook (`hosts: workers`) run unchanged.
- **Copy the group `variables` exactly.** They are part of the execution hash, so a copy that
  differs puts the dependent plan on a different revision than the original inventory would have.

Remember what the label means: *this version was applied here at some point*. It is not a freshness
or health signal, and a dependent is **not** re-run when the provider changes — see
[Scheduling and execution modes](./scheduling-and-modes.md#dependencies-do-not-re-trigger-a-plan).

### Seeing what an inventory is waiting for

An inventory gated on a dependency resolves fewer hosts than you wrote it for, which on its own
looks exactly like a typo in the key. The inventory says which it is: `.status.waitingHosts` (the
`Waiting` column) counts the Nodes kept out by a dependency alone, and `.status.dependencies` says
what each group is waiting on.

```console
$ kubectl get clusterinventory workers-with-containerd
NAME                      HOSTS   WAITING
workers-with-containerd   3       5

$ kubectl get clusterinventory workers-with-containerd -o jsonpath='{.status.dependencies}' | jq
[
  {
    "group": "workers",
    "key": "platform.plan.ansible.cloudbending.dev/containerd-config",
    "providerNamespace": "platform",
    "providerName": "containerd-config",
    "requirement": "Ge 1.4.0",
    "waiting": 5,
    "satisfied": 3
  }
]
```

Read it as "3 of 8 of this group's Nodes have got past `containerd-config`". A Node counts towards
those numbers when it satisfies everything *else* the group asks for, so a Node your `node-role`
selector excludes is not reported as waiting — it is simply not this group's Node. A Node held back
by two dependencies is counted under both, since neither provider finishing releases it on its own.

The provider is named by **decoding the key**, not by looking the plan up. A dependency on a plan
nobody has therefore reads as waiting for it for ever — which is what a mistyped key looks like, and
why the name is printed: `nosuch/typo` in `providerName` is the typo staring back at you.

Which Nodes they are is a label query away. Select on the group's other terms and show the
dependency key as a column, which holds each Node's version:

```console
$ kubectl get nodes -l 'node-role.kubernetes.io/worker' -L 'platform.plan.ansible.cloudbending.dev/containerd-config'
```

Every Node with an empty column is waiting. So is one showing a version the requirement does not
accept, such as `1.3.0` against `Ge 1.4.0`, because a label selector cannot compare versions. For an
`Exists` requirement the empty ones are all of them, and a selector can list just those:

```console
$ kubectl get nodes -l 'node-role.kubernetes.io/worker,!platform.plan.ansible.cloudbending.dev/containerd-config'
```

Two limits worth knowing. These counts are the **inventory's**, so they are taken before any
[`NodeAccessPolicy`](../cluster-operators/node-access-policies.md) clamp a plan using this inventory
is subject to: a Node reported as satisfied may still be out of a given plan's reach.

And `Waiting` is the whole inventory's, not any one group's: it counts the Nodes **no** group of this
inventory takes. A Node one group is waiting for while another already resolves it is a host of this
inventory, so it is counted under `Hosts` and not under `Waiting` — which is what makes the two
columns add up rather than double-count a machine. An inventory with one broad group and one gated
group can therefore sit at `Waiting: 0` while `.status.dependencies` still reports a group waiting,
and that is the honest answer to each question. So read `Waiting: 0` as "nothing is kept out of this
inventory by a dependency"; if its host count is still lower than you expect, the missing Nodes fail
something other than a dependency — the selector, or the policy. For what an individual *group* is
waiting for, read `.status.dependencies`.

Three things are flagged rather than counted, when a dependency can never be satisfied as written:
`invalidValue`, `malformedTerm` and `unparseableHosts`. See
[A dependency never becomes satisfied](./results-and-troubleshooting.md#a-dependency-never-becomes-satisfied).

## Group variables

Each group may carry a `variables` map, rendered as Ansible **group vars** for every Node the group
resolves to. Use it to pin node facts the playbook author should not need to know — most often
`ansible_python_interpreter`, so playbooks don't emit interpreter-discovery warnings:

```yaml
spec:
  hosts:
    - name: controlplanes
      matchLabels:
        node-role.kubernetes.io/control-plane: "true"
      variables:
        ansible_python_interpreter: /usr/bin/python3
```

Group variables are part of a plan's execution hash, so changing one re-applies the playbook to the
affected Nodes on the next run. The connection variables the operator manages itself — `ansible_host`,
`ansible_port`, `ansible_user`, and the `ansible_ssh_*` options — are rejected: they are wired from
managed SSH, and a plan that references an inventory setting one does not run until you remove it.

## Tolerations

To reach a tainted Node such as a control-plane node, the managed-SSH proxy pod for that Node must
tolerate its taints. Set `spec.tolerations` on the `ClusterInventory`; they are applied to the proxy
pods this inventory creates. `tolerations: [{ operator: Exists }]` tolerates everything, which is
safe here because each proxy pod is pinned to one exact Node, so tolerating all taints only lets it
schedule onto *that* Node.

A plan may target Nodes through several inventories at once, and each Node's proxy gets the
tolerations of the inventories that name it. A Node named by more than one gets all of theirs
together — for the same reason: a toleration it does not need cannot send its proxy anywhere else,
while a missing one would leave that Node unreachable for the run.

```yaml
spec:
  tolerations:
    - operator: Exists
```

The `not-ready` and `unreachable` taints Kubernetes applies to a `NotReady` Node are tolerated
automatically — you do not need to list them. See [NotReady nodes](#notready-nodes).

## How managed SSH reaches a Node

You do not configure any of this; it is background for the security model and for troubleshooting.
For a run targeting Nodes, the operator:

1. Schedules a short-lived **proxy pod** onto each targeted Node. The pod runs a real `sshd` and is
   granted just enough privilege (`hostPID`, a host `/proc` mount, `CAP_SYS_ADMIN` +
   `CAP_SYS_PTRACE`) that each SSH session can `nsenter` into the Node's host namespaces, making the
   session `root` on the Node. The pod does not use `privileged: true`, `hostNetwork`, or `hostIPC`.
2. Mints a fresh SSH **host certificate** for that run from the operator's in-memory certificate
   authority, and a matching **client certificate** for the Job. Certificates are per-run and
   short-lived, so a run can authenticate only to *its own* proxy pods — even a re-run of the
   same unchanged plan cannot reach the pods of the run it replaced.
3. Locks each proxy pod's ingress to that run's Job with a NetworkPolicy.
4. Renders the inventory so Ansible dials the proxy pod and verifies the Node's host certificate.
5. Holds the Job back, in a `managed-ssh-preflight` init container, until every proxy it can expect
   to reach actually answers. See [Preflight connectivity check](#preflight-connectivity-check).
6. Tears the proxy pods, their Secrets, and the NetworkPolicy down when the run finishes.

There is **no standing agent or DaemonSet** on your Nodes: proxy pods exist only for the duration of
a run. The security properties of this path — per-run certificate isolation, the in-memory CA,
and why `NodeAccessPolicy` is mandatory — are covered in
[Security model](../cluster-operators/security.md).

## Preflight connectivity check

A proxy pod being `Ready` does not yet mean your Job can reach it. Kubelet probes the pod from its
own Node, whereas the NetworkPolicy that admits your Job to the proxies selects the Job's pod by
label — so the cluster network can only start programming that rule once the Job pod exists. On a
run targeting several Nodes at once, the proxy on the Job's own Node answers immediately while the
remote ones briefly refuse connections.

To keep that from surfacing as a failed run, the operator adds a `managed-ssh-preflight` init
container that waits on port 22 of every proxy this run can expect to reach before
`ansible-playbook` starts. Hosts whose proxy never became `Ready` are left out deliberately: they are
already unreachable for this run, and waiting on them could only burn the gate's budget at the
expense of the hosts that can still be rescued.

Once it starts, the gate never fails a run. After 60 seconds it starts Ansible regardless, and any
proxy still not answering is reported **unreachable** for that run and retried on the next one,
exactly as it would have been; an unexpected error inside the gate is logged and otherwise ignored
for the same reason. Starting is the part your image has to make possible: the container runs
`python3` from the plan's own image, so an image without it on `PATH` fails here instead, before
Ansible has run at all — see [`python3` must be on
`PATH`](./playbook-plans.md#python3-must-be-on-path).

If a run seems slow to start, the gate says what it was waiting for:

```console
$ kubectl logs job/<job-name> -c managed-ssh-preflight
preflight: node-a (10.42.1.7:22) reachable after 0.0s
preflight: node-b (10.42.3.9:22) reachable after 1.5s
preflight: all 2 managed-ssh proxies reachable after 1.5s
```

Nothing about this is configurable, and playbooks do not need their own `wait_for` or `pause` tasks
to work around connection timing.

## NotReady nodes

A Node matched by a `ClusterInventory` stays in the inventory even when it is `NotReady`. The operator
still schedules the proxy pod onto it and waits for the pod to become Ready. While it waits, the
`PlaybookPlan` carries a `WaitingForNodes` condition naming the pending Node(s).

If the proxy pod does not become Ready within the wait window, the run proceeds without that Node.
There is no address to reach it at, so the run does not try: it passes `--limit '!<node>'` to
`ansible-playbook`, which excludes the Node from execution while leaving it in the inventory. It is
never recorded as `Failed`, since no task ever ran on it; which [outcome
](./results-and-troubleshooting.md#per-host-outcomes) it does get in `.status.hostsStatus` depends on
what the operator saw at launch:

- the Node was itself `NotReady` — `Unreachable`. For a `OneShot` plan its return to `Ready` starts
  the next run on its own, so this heals without anyone touching the plan; a `Recurring` plan heals
  at its next tick, which is the only thing that ever starts a run for it.
- the Node was `Ready` and only the proxy pod failed to come up — `NotReached`. Nothing about the
  Node is going to change, so nothing wakes the plan for it. See
  [Unreachable Nodes and the attempt budget](#unreachable-nodes-and-the-attempt-budget) below and
  [Hosts show `NotReached`](./results-and-troubleshooting.md#hosts-show-notreached).

The wait window is set by the cluster operator and shrinks the longer a Node has been unreachable
(see [Deployment](../cluster-operators/deployment.md)).

Excluding rather than dropping is what keeps the inventory honest. The Node stays a member of its
groups, so a playbook templating a cluster member list out of `groups['workers']` still sees the
whole fleet — but nothing dials it, so a playbook that aborts on the first unreachable host
(`any_errors_fatal: true`, a `serial` batch, `max_fail_percentage`) runs to completion on the hosts
that are up instead of stopping at the one that is not.

The one thing exclusion gives up is `max_fail_percentage` as a fleet-availability check: an excluded
Node is not part of the denominator, so a rollout guarded that way no longer aborts because too much
of the fleet is unavailable. It still aborts on hosts that were reached and failed.

The same bounded wait applies when a proxy from an interrupted credential reset is still terminating.
It is never reused, even if Kubernetes still reports it `Ready`; after the deadline the Node is marked
unreachable for that run rather than holding the run and its host locks indefinitely.

### Holding instead of starting

All of the above is about a run that has already started. A `OneShot` plan that has *not* started one
asks a cheaper question first: if **every** Node the run would target is `NotReady`, there is nothing
for the run to do, so the plan holds instead of starting it. It carries a `WaitingForNodes` condition
with reason `NodesNotReady`, and `.status.summary` names the Nodes it is waiting for. `Ready` is
`False` with the same reason for as long as the hold lasts — the phase keeps the last run's
verdict, but a plan holding a run has hosts it has not applied the current revision to.

Holding rather than running matters because the run would achieve nothing and take the full wait
window to find that out — a proxy pod per Node, every host lock held for the duration, and a `Failed`
verdict that says nothing about the playbook. A held plan does none of that, and is released the
moment one of those Nodes reports `Ready` again, which the operator notices at once.

The hold is all-or-nothing on purpose. A run that can still reach *some* of its hosts goes ahead and
reaches them; the `NotReady` ones stay in its inventory and are reported unreachable in the result
rather than quietly dropped from it. `Recurring` plans never hold: their contract is to re-apply at
every tick against whatever is reachable then.

A plan can stay held indefinitely, and for a Node that is never coming back that is the intended
resting state. It reads
[`HostsUnreachable`](./results-and-troubleshooting.md#phases) rather than `Failed` for as
long as that lasts, provided every host it did not apply to was one nothing could reach — the
playbook is fine, and the plan is waiting for hardware. The condition says exactly which Node. Removing the Node from the cluster
or from the inventory's selector is what ends it.

The hold is asked before a run starts, so it cannot catch a proxy pod that fails *after* it passed.
If that leaves a started run with every host excluded, the run is recorded straight away without a
Job: there is no host for a playbook to run against. A host on a `NotReady` Node is `Unreachable`; a
host whose Node was `Ready` but whose proxy failed is `NotReached`. A run containing only
`Unreachable` hosts leaves the plan `HostsUnreachable`, while any `NotReached` host makes it
`Failed`. It spends an attempt or not by the same rule as any other run — see below — and because no
Job exists, there are no run logs for it. `.status.summary` and the `Play` record are where to look.

### Unreachable Nodes and the attempt budget

A run that can still reach some of its hosts does start, and it ends `Failed` if it could not reach
the rest. That verdict stands — the result names every host that was not reached — but it does not
cost the plan one of its [attempts](./scheduling-and-modes.md#retries), provided both halves hold:

- the run **applied the playbook to at least one host**, and
- every host that did *not* succeed sat on a Node that was already `NotReady` when the run launched.

Then the run applied everything there was to apply, and a `OneShot` plan's budget is reset exactly as
a fully successful run resets it. What the plan is waiting for is the Node, not another try, and the
next try would be identical. On a scheduled plan the Node's return still starts that run within the
same tick's `startingDeadlineSeconds` window, whatever `maxAttempts` is; once the window has closed
it waits for the next tick.

The first half is what keeps a plan from running forever against a Node that keeps coming and going.
A refund is credit for progress, so a run that reached nobody spends its attempt however good its
excuse — and a Node that alternates faster than the plan converges is exactly the case that would
otherwise refund every attempt it costs. In the ordinary case this half never binds: a plan whose
Nodes are *stably* down is held before it starts a run at all, and one with a healthy Node alongside
the down one is applying the playbook to it.

The cost is deliberate. A plan whose Nodes all go down between the readiness check and the launch
spends an attempt, and after `maxAttempts` of that it stops — so a Node that flaps that many times
and then genuinely returns needs someone to touch the plan (bump `maxAttempts`, or edit it) rather
than converging on its own. Bounding the loop is worth more than converging through a flap. Once the
budget is gone the Node stops waking the plan too, since there is no longer anything the plan is
allowed to do about the Node coming back; touching the plan is what restores both.

Only Nodes the operator recorded **at launch** count. Two failures that can look the same from the
outside do spend an attempt, because no Node coming back resolves either:

- a Node that was `Ready` when the run started and went down *while it ran* — a playbook that reboots
  its target, say. The operator did reach it, and the run genuinely tried. What keeps the *following*
  attempt from being spent is the hold above, for as long as the Node stays down.
- a Node Kubernetes reports `Ready` whose proxy pod never came up anyway — an untolerated taint, a
  failing image pull, a rejecting admission webhook. That is a configuration problem, and it is the
  one the attempt budget exists to stop retrying. Such a host is reported
  [`NotReached`](./results-and-troubleshooting.md#hosts-show-notreached), not `Unreachable`: the Node
  is already `Ready`, so its heartbeats have nothing left to announce and the operator does not wake
  the plan on them. The plan reads `Failed` rather than `HostsUnreachable`, which is the honest
  answer — there is a pod spec to fix, not a machine to wait for.

A run whose recap could not be read at all (`Unknown`, see
[Results](./results-and-troubleshooting.md)) always spends its attempt: nothing proves any of its
hosts was reached. So does a run the playbook aborted, since its surviving hosts are
[`Incomplete`](./results-and-troubleshooting.md#hosts-show-incomplete) rather than applied — the
down Node is not what stopped it, and the playbook failure is what needs the attempt.

## Requirements and limitations

- The operator must be installed and your namespace **enrolled** (see
  [Deployment](../cluster-operators/deployment.md)).
- A `NodeAccessPolicy` must grant your namespace the Nodes you want to reach, or the inventory
  resolves to nothing for you.
- The proxy image must be a real OpenSSH `sshd` image the cluster can pull. This is an operator
  concern; the default and how to pin it are covered under
  [Deployment](../cluster-operators/deployment.md).
- Managed SSH targets **Linux** Nodes.

## When to use a StaticInventory instead

`ClusterInventory` is only for machines that are **Kubernetes Nodes of this cluster**. To reach
anything else — external servers, appliances, network gear, or nodes of a *different* cluster — use a
`StaticInventory` with your own SSH key. See [Targeting external hosts](./external-hosts.md).
