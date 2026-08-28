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
For each targeted Node in a run, the operator:

1. Schedules a short-lived **proxy pod** onto that exact Node. The pod runs a real `sshd` and is
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

If the proxy pod does not become Ready within the wait window, the run proceeds without that Node:
Ansible reports it **unreachable** for the run, and the Node is retried on the next run, so it heals on
its own once it recovers. The wait window is set by the cluster operator and shrinks the longer a Node
has been unreachable (see [Deployment](../cluster-operators/deployment.md)).

The same bounded wait applies when a proxy from an interrupted credential reset is still terminating.
It is never reused, even if Kubernetes still reports it `Ready`; after the deadline the Node is marked
unreachable for that run rather than holding the run and its host locks indefinitely.

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
