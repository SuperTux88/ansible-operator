# Deployment

The operator ships as a Helm chart under `chart/`. This page covers installing it, the namespace and
Pod-Security requirements it imposes, the managed-SSH proxy image, and the two fail-closed knobs —
namespace enrollment and node access — you have to open deliberately.

## Install

Install into its **own dedicated namespace**:

```sh
helm install --create-namespace -n ansible-system ansible-operator ./chart
```

Do **not** create `PlaybookPlan`s or inventories in the operator's own namespace — those belong in
tenant namespaces. The operator namespace is where its runtime machinery lives: per-run Leases and
the managed-SSH proxy pods, Secrets, and NetworkPolicies. (The admin-authored `NodeAccessPolicy`
objects are cluster-scoped and live in no namespace.) Keeping it separate means only this one
namespace needs the privileged-pod exception below.

## Pod Security Admission

Managed-SSH proxy pods (created dynamically by the operator at runtime, not by the chart) run with
`hostPID: true` and added `SYS_ADMIN`/`SYS_PTRACE` capabilities so each SSH session can `nsenter` into
the target Node's namespaces. That combination is only permitted under the **`privileged`** Pod
Security Standard, so the operator's namespace must carry the label:

```sh
kubectl label namespace ansible-system pod-security.kubernetes.io/enforce=privileged
```

The proxy pods do not use `privileged: true`, `hostNetwork`, or `hostIPC` — only `hostPID` plus the
two capabilities. Because this exception is scoped to the single operator namespace, tenant
namespaces need no Pod-Security relaxation.

## SELinux-enforcing nodes

On SELinux-enforcing Nodes the proxy pods additionally set
`securityContext.seLinuxOptions.type: spc_t` ("super-privileged container"), the label that lets the
`nsenter`'d process touch the host filesystem. This is applied automatically, is a no-op on
non-SELinux nodes, and needs no action from you.

## The managed-SSH proxy image

Cluster-node access needs a **real OpenSSH `sshd`** image for the proxy pods; the operator's own image
is distroless and cannot serve this role. It is configured via the chart's `managedSsh.proxyImage`.

The default is the first-party, minimal, statically-linked `sshd` image published alongside the
operator (`ghcr.io/webd97/ansible-operator-sshd`). With `tag` left empty it tracks the chart
appVersion, so it moves in lockstep with the operator on upgrade.

**This is a node-root pod, so treat the image as node-root supply chain.** In production, pin it to a
digest from a registry you trust — set `tag: ""` and put the digest in `repository`:

```yaml
# values.yaml
managedSsh:
  proxyImage:
    repository: my-registry.example.com/ansible-operator-sshd@sha256:<digest>
    tag: ""
```

The value is rendered into the operator's config and consumed at pod-build time; changing it rolls
the operator (via a `checksum/config` annotation) rather than hot-reloading.

## NotReady nodes

When a `ClusterInventory` targets a `NotReady` Node, the operator still schedules its proxy pod and
waits for the pod to become Ready. If it does not become Ready in time, the run proceeds without that
Node — Ansible reports it unreachable, and it is retried on the next run. The wait applies only to a
pod that has not yet started; a pod that has reached `Running` is waited on until Ready as usual.

The wait scales with how long the Node has been silent (its last `Ready` heartbeat): a Node that only
just went `NotReady` is given the full wait, one silent for longer is given up on sooner. Tune it via
`managedSsh.readiness`:

```yaml
# values.yaml
managedSsh:
  readiness:
    graceSeconds: 600         # full wait for a node whose last heartbeat is within thresholdDays[0]
    aggressiveness: 2         # divide the wait at each further threshold
    thresholdDays: [3, 7, 30] # heartbeat-age boundaries; past the last one the node is given up at once
```

The defaults wait 600 / 300 / 150 / 0 seconds for a Node last seen within 3 / 7 / 30 / more days.
Like the other config values, a change rolls the operator rather than hot-reloading.

## Enrolled namespaces

The operator's cluster-wide RBAC does **not** include `secrets`, `jobs`, or `pods`. Those verbs are
granted per-namespace, only for **enrolled** namespaces, via a `Role`/`RoleBinding` the chart renders.
The enrolled set is the operator's own namespace plus the chart's `watchNamespaces`:

```yaml
# values.yaml
watchNamespaces:
  - team-a
  - team-b
```

A `PlaybookPlan` created in a namespace that is **not** enrolled is refused with
`status.phase = UnauthorizedNamespace`, before any Secret is read or Job created. There is no "all
namespaces" option: this allowlist bounds an operator compromise to the enrolled namespaces rather
than the whole cluster.

Two consequences to plan for:

- **Enrolling is an admin action that requires a restart.** The config is read once at startup;
  editing `watchNamespaces` and running `helm upgrade` rolls the operator so it re-reads the set. It
  is not hot-reloaded. (The same is true of `managedSsh.proxyImage`.)
- **The operator can read *and delete* Secrets in every enrolled namespace.** Enroll only namespaces
  **dedicated to Ansible ops**, not general-purpose application namespaces, so this power covers as
  few unrelated Secrets as possible. See
  [Security model → the blast radius you accept](./security.md#blast-radius).

Under the hood this is driven by a small TOML config (`watch_namespaces`, `proxy_image`) that the
chart renders into a mounted ConfigMap. For local development you can point the binary at a config
file directly with `run --config <path>` and set `POD_NAMESPACE` (the operator's own namespace, always
enrolled).

## ServiceAccount tokens

The operator ServiceAccount disables implicit token mounting, while the operator Deployment
explicitly requests the token it needs for Kubernetes API access. Managed-SSH proxy pods do not
mount a ServiceAccount token. An Ansible Job receives a token only when its `PlaybookPlan` sets
`serviceAccountName`.

## Workload security contexts

The chart sets `allowPrivilegeEscalation: false` on the operator container. Managed-SSH proxy
containers cannot use that setting because Kubernetes treats their required `SYS_ADMIN` capability
as privilege escalation. The proxy receives only the capabilities and SELinux type required for
node access. Admission policies should scope any required exception to pods labelled
`ansible.cloudbending.dev/component=managed-ssh-proxy` instead of excluding the whole namespace.

## Custom Resource Definitions

The chart bundles the four CRDs (`PlaybookPlan`, `ClusterInventory`, `StaticInventory`,
`NodeAccessPolicy`) under `crds/`. Following Helm's convention, `crds/` is install-only and is
**not** upgraded by `helm upgrade`; when the CRDs change between versions, apply them manually:

```sh
kubectl apply -f chart/crds/
```

The bundled manifests are a static snapshot generated from the binary itself
(`ansible-operator crds`); the regeneration procedure lives in `chart/README.md`.

## Grant node access

Installing the operator and enrolling a namespace is **not** enough for cluster-node playbooks: node
access is itself fail-closed. Until you author a `NodeAccessPolicy`, every namespace resolves to
**zero** Nodes and managed-SSH plans target nothing. Continue at
[Node access policies](./node-access-policies.md).
