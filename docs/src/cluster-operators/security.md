# Security model

This page summarises what you are trusting when you install the operator, and the mechanisms that
bound that trust. The full analysis — every threat, its mitigation, and the numbered invariants
(INV-1…INV-7) enforced by unit tests — is `THREAT_MODEL.md` in the repository. **If this page and
`THREAT_MODEL.md` disagree, `THREAT_MODEL.md` is correct.**

## Managed SSH is node-root

Reaching a cluster Node via a `ClusterInventory` means a managed-SSH session that is **`root` on that
Node** — it `nsenter`s into the host namespaces of a proxy pod running with `hostPID` and
`SYS_ADMIN`/`SYS_PTRACE`. This is the intended capability (you cannot patch a Node's OS without it),
and the rest of the security model governs *who* may obtain it, over *which* Nodes, and for *how
long*. External hosts reached via a `StaticInventory` are a different, lower-privilege path: there the
operator is just an SSH client using a key you provided.

## Two fail-closed gates

Both default to deny. Neither can be skipped:

1. **Namespace enrollment** bounds *where the operator itself has power*. Its cluster RBAC omits
   `secrets`/`jobs`/`pods`; those are granted per-namespace only for enrolled namespaces. A plan in an
   un-enrolled namespace is refused (`UnauthorizedNamespace`). There is no "all namespaces" option.
   → [Deployment → enrolled namespaces](./deployment.md#enrolled-namespaces)
2. **Node access policies** bound *which Nodes a tenant may reach*. A namespace with no matching
   `NodeAccessPolicy` resolves to **zero** Nodes; an empty selector matches nothing, not everything.
   → [Node access policies](./node-access-policies.md)

## How node access is enforced

A `NodeAccessPolicy` is a cluster-scoped resource, so it is authored only by principals with
cluster-level RBAC (i.e. cluster admins) — a **different principal** than the tenant who authors the
namespaced `ClusterInventory`. Enforcement is a set **intersection**: a plan's requested Nodes are
intersected with the union of Nodes the matching policies grant that namespace, so it can only ever
*shrink* the request. A forged, buggy, or over-broad `ClusterInventory` can never reach a Node no
policy allowed. The clamp runs at inventory-resolve time, on **every** reconcile, **before** any proxy
pod, Secret, or NetworkPolicy is created, against a **live** Node read.

## How runs are isolated from each other

Cross-run isolation is enforced at the **certificate** layer, not merely by network rules:

- The operator runs its **own SSH certificate authority**, generated **in memory at startup**. The CA
  private key is never written to a Secret, never persisted to etcd, never logged. **Restarting the
  operator rotates the CA** and invalidates every outstanding certificate.
- Each run gets fresh, short-lived host and client certificates. Each proxy pod's
  authorized-principals list contains **only its own run's execution hash** — never `root`, never a
  wildcard — so a run can authenticate only to *its own* proxy pods.
- A per-run **NetworkPolicy** locks each proxy pod's ingress to that run's Job. This is defense in
  depth on top of the certificate isolation, not the primary control.
- Proxy pods, their per-run Secrets, and the NetworkPolicy are **torn down when the run ends** — there
  is no standing SSH surface on your Nodes between runs.

## Privileges the proxy pods hold

Proxy pods take the **minimum** that makes `nsenter`-to-host work: `hostPID: true`, a host `/proc`
bind-mount, `CAP_SYS_ADMIN` + `CAP_SYS_PTRACE`, and (on SELinux nodes) the `spc_t` label. They do
**not** set `privileged: true`, `hostNetwork`, or `hostIPC`. Each is pinned to exactly one Node. The
proxy does not mount a ServiceAccount token. It cannot set `allowPrivilegeEscalation: false` because
Kubernetes treats the required `SYS_ADMIN` capability as privilege escalation. The
image they run is the node-root supply-chain surface you must own — the default is the first-party
image published with the operator; in production pin it to a trusted digest (see
[Deployment → the proxy image](./deployment.md#the-managed-ssh-proxy-image)).

## The playbook pod's Kubernetes access

The pod that runs `ansible-playbook` carries **no** Kubernetes API token unless the plan sets
`serviceAccountName` — the operator sets `automountServiceAccountToken: false` by default, so a
playbook that never asked for cluster access cannot reach the API at all. When a plan does set
`serviceAccountName`, the run acts with **that ServiceAccount's RBAC**. Because a plan author picks
any ServiceAccount in the plan's namespace, this is a within-namespace escalation surface: an author
who can create `PlaybookPlan`s can run a pod as any ServiceAccount there. It is bounded by the same
enrollment fence — enrolled namespaces should be **dedicated to Ansible ops**, so every ServiceAccount
in one is already inside that trust boundary — and by the fact that the author already runs arbitrary
playbook code (node-root over managed SSH). Keep only ServiceAccounts you would trust a playbook to
assume in an enrolled namespace.

## Inventory group variables

A `ClusterInventory` or `StaticInventory` group may set `variables`, rendered as Ansible group vars
for its hosts. The operator **rejects** the connection variables it manages itself — `ansible_host`,
`ansible_port`, `ansible_user`, `ansible_timeout`, and the `ansible_ssh_*` options — so an inventory
author cannot use group vars to redirect a dial or weaken host-key checking; a plan that references
such an inventory fails to reconcile until the variable is removed. Everything else an author sets is
data the playbook they already control would receive anyway, so this adds no reach beyond authoring
the playbook itself.

## Blast radius

What a compromise of the operator (or of a tenant allowed to author a `ClusterInventory`) can and
cannot reach:

- **Bounded to enrolled namespaces.** The operator can read *and delete* Secrets, and create Jobs, in
  **every enrolled namespace**, but nowhere else. This is why you should **enroll only namespaces
  dedicated to Ansible ops**, never general application namespaces: a dedicated namespace holds only
  Secrets that are already part of the Ansible trust boundary.
- **Bounded to policy-granted Nodes.** Even a fully forged request cannot reach a Node outside the
  intersection of the admin-authored policies.
- **No persistent node foothold from the mechanism itself.** Proxy infra is per-run and ephemeral, and
  the CA is in-memory and rotates on restart. What a *playbook* does to a Node is up to the playbook —
  that is the tenant's power, gated by the two fences above.

## Invariants

The properties above are pinned by seven invariants (INV-1…INV-7 in `THREAT_MODEL.md` §7), enforced by
unit tests. In brief: fail-closed selectors (INV-1); enforcement is intersection-only and can only
remove hosts (INV-2); it runs before any proxy infra, every reconcile (INV-3); cross-run isolation is
per-run cert principals (INV-4); the Node allow-set is a live read (INV-5); the CA private key never
leaves the process (INV-6); proxy pods are labelled so cleanup can never sweep the ansible Job pod
(INV-7). If you are modifying the operator, do not regress these without an explicit, deliberate
decision.
