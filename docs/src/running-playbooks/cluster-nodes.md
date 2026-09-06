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
  `Exists`, `DoesNotExist`.

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
`ansible-playbook`, which excludes the Node from execution while leaving it in the inventory. The
Node is recorded as [`Unreachable`](./results-and-troubleshooting.md#per-host-outcomes) in
`.status.hostsStatus`, not `Failed`, since no task ever ran on it, and it is retried on the next run,
so it heals on its own once it recovers. The wait window is set by the cluster operator and shrinks
the longer a Node has been unreachable (see [Deployment](../cluster-operators/deployment.md)).

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
with reason `NodesNotReady`, and `.status.summary` names the Nodes it is waiting for.

Holding rather than running matters because the run would achieve nothing and take the full wait
window to find that out — a proxy pod per Node, every host lock held for the duration, and a `Failed`
verdict that says nothing about the playbook. A held plan does none of that, and is released the
moment one of those Nodes reports `Ready` again, which the operator notices at once.

The hold is all-or-nothing on purpose. A run that can still reach *some* of its hosts goes ahead and
reaches them; the `NotReady` ones stay in its inventory and are reported unreachable in the result
rather than quietly dropped from it. `Recurring` plans never hold: their contract is to re-apply at
every tick against whatever is reachable then.

A plan can stay held indefinitely, and for a Node that is never coming back that is the intended
resting state — the condition says exactly what it is waiting for. Removing the Node from the cluster
or from the inventory's selector is what ends it.

The hold is asked before a run starts, so it cannot catch a proxy pod that fails *after* it passed.
If that leaves a started run with nothing it can reach, no Job is created for it: there is no host
for a playbook to run against, so the run is recorded straight away as `Failed` with every host
`Unreachable`. It spends an attempt or not by the same rule as any other run — see below — and
because no Job exists, there are no run logs for it. `.status.summary` and the `Play` record are
where to look.

### Unreachable Nodes and the attempt budget

A run that can still reach some of its hosts does start, and it ends `Failed` if it could not reach
the rest. That verdict stands — the result names every host that was not reached — but it does not
cost the plan one of its [attempts](./scheduling-and-modes.md#retries): if every host that did not
succeed sat on a Node that was already `NotReady` when the run launched, the run applied everything
there was to apply, and a `OneShot` plan's budget is reset exactly as a fully successful run resets
it. What the plan is waiting for is the Node, not another try, and the next try would be identical.

Only Nodes the operator recorded **at launch** count. Two failures that can look the same from the
outside do spend an attempt, because no Node coming back resolves either:

- a Node that was `Ready` when the run started and went down *while it ran* — a playbook that reboots
  its target, say. The operator did reach it, and the run genuinely tried. What keeps the *following*
  attempt from being spent is the hold above, for as long as the Node stays down.
- a Node Kubernetes reports `Ready` whose proxy pod never came up anyway — an untolerated taint, a
  failing image pull, a rejecting admission webhook. That is a configuration problem, and it is the
  one the attempt budget exists to stop retrying.

A run whose recap could not be read at all (`Unknown`, see
[Results](./results-and-troubleshooting.md)) always spends its attempt: nothing proves any of its
hosts was reached.

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
