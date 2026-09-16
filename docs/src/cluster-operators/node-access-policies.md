# Node access policies

A `NodeAccessPolicy` is the admin-authored ceiling on which cluster **Nodes** a namespace's
`ClusterInventory` resources may reach. Because a `ClusterInventory` confers
[node-root](./security.md#managed-ssh-is-node-root), any namespace allowed to create one could
otherwise target *any* Node — the policy is what stops that.

> **Fail-closed, always on.** A namespace with **no** matching policy resolves to **zero** allowed
> Nodes. There is no default-allow and no way to disable the check — until you author a policy,
> managed-SSH plans target nothing. This is the most common reason a `ClusterInventory` resolves to no
> hosts.

## Who can author them

`NodeAccessPolicy` is a **cluster-scoped** resource — it has no namespace. Creating one requires
cluster-level RBAC (the `nodeaccesspolicies` resource in the `ansible.cloudbending.dev` API group),
which makes this an *admin* control rather than a tenant one: a tenant with rights only in their own
namespace cannot create a policy that widens their own Node access. Enforcement considers **every**
`NodeAccessPolicy` in the cluster.

## What a policy says

Each policy maps a set of **namespaces** to a ceiling set of **Nodes** with two label selectors (each
a `matchLabels`/`matchExpressions` selector, like Kubernetes' own):

- `namespaceSelector` — which namespaces this policy grants access to. Kubernetes stamps every
  namespace with `kubernetes.io/metadata.name: <name>`, so you target a single namespace by that
  label.
- `nodeSelector` — the ceiling: the Nodes those namespaces may resolve. A `ClusterInventory`'s
  resolved Nodes are **intersected** with the Nodes matching this selector.

```yaml
apiVersion: ansible.cloudbending.dev/v1beta1
kind: NodeAccessPolicy
metadata:
  name: business-team            # cluster-scoped — no namespace
spec:
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: business-app
  nodeSelector:
    matchExpressions:
      - { key: node-pool, operator: In, values: [business] }
```

To cover several namespaces in one policy, use `matchExpressions` on the `namespaceSelector`, e.g.
`{ key: team, operator: In, values: [business, payments] }`.

Both selectors take the same operators a `ClusterInventory` group does — `In`, `NotIn`, `Exists`,
`DoesNotExist`, and the ordered `Gt`, `Ge`, `Lt`, `Le`, which compare a label value against one
value as a version (see [Comparing versions](../running-playbooks/cluster-nodes.md#comparing-versions)).
A ceiling written with an ordered operator is worth reading twice, because the label it orders is
usually one a plan publishes — see below.

## Matching every Node

An **empty** selector (`{}`) matches **nothing**, not everything — the opposite of Kubernetes' usual
convention. To grant *all* Nodes, match a label every Node carries, explicitly:

```yaml
apiVersion: ansible.cloudbending.dev/v1beta1
kind: NodeAccessPolicy
metadata:
  name: cluster-admins
spec:
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: ansible-system
  nodeSelector:
    matchExpressions:
      - { key: kubernetes.io/hostname, operator: Exists }   # every Node has a hostname
```

## How multiple policies combine

A namespace's effective allow-set is the **union** of the `nodeSelector`s of **every** policy whose
`namespaceSelector` matches it. That union is then intersected with each `ClusterInventory`'s resolved
Nodes at run time. So you can layer policies — a broad baseline plus narrower grants — and a namespace
gets the sum of what any matching policy allows, never more than the Nodes that actually exist.

## Selecting on a plan's dependency label delegates part of the ceiling

A policy's `nodeSelector` may name one of the labels a plan publishes through `spec.provides`
(`<namespace>.plan.ansible.cloudbending.dev/<plan-name>`) — for example, to say that a namespace may
only reach Nodes a hardening plan has finished with, optionally at a minimum version:

```yaml
  nodeSelector:
    matchExpressions:
      - { key: platform.plan.ansible.cloudbending.dev/hardening, operator: Ge, values: ["2.0.0"] }
```

That is a legitimate and useful thing to express, but be clear about what it means.

No plan can grant *itself* access this way. The label only ever appears on Nodes where the providing
plan ran successfully, and that plan's runs were already bounded by its own namespace's ceiling — so
a label can never point past where its author could already reach.

What such a policy does is **delegate**. The selected namespace's ceiling then follows:

- what the providing plan's tenant does, up to that plan's own ceiling; and
- anyone with root on a Node, who can forge the label for *that* Node through the kubelet (the
  operator's keys are not under a `NodeRestriction`-reserved prefix). Every managed-SSH playbook has
  exactly that root.

So treat it as handing part of the decision to the providing plan's owner. For a fixed ceiling,
keep using labels only an administrator can set — `kubernetes.io/metadata.name` for namespaces,
admin-managed node pool labels for Nodes.

## Observing a policy

Each policy's controller keeps its `.status` current:

- `matchedNamespaces` — the namespaces currently selected.
- `allowedNodeCount` / `allowedNodes` — the size and the concrete, sorted list of Nodes the ceiling
  currently resolves to. `allowedNodeCount` is surfaced as the `Allowed nodes` printer column
  (`kubectl get nodeaccesspolicy`).

When a tenant reports a `ClusterInventory` resolving to nothing, compare that inventory's
`.status.hostCount` (Nodes matched *before* policy clamping) with the `allowedNodes` of the policy that
should cover their namespace — the gap is exactly what the ceiling removed.
