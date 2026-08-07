# ansible-operator Helm chart

## Install

```sh
helm install --create-namespace -n ansible-system ansible-operator ./chart
```

The operator must be installed into its own dedicated namespace — see the comment above
`serviceAccount` in `values.yaml` for why. Don't create PlaybookPlans/ClusterInventories/
StaticInventories in that same namespace; those belong in your own tenant namespaces.

Optional egress NetworkPolicies are configurable through `networkPolicy` in `values.yaml`. Operator
and playbook policies default to `[{}]` ("policy present, egress unrestricted"); the managed-SSH
proxy policy defaults to an empty array (`[]`), NetworkPolicy's deny-all-egress, because the proxy
only needs inbound SSH. Do not use `[]` for the operator or playbook unless deliberately blocking
their outbound connections.

### Pod Security Admission

Managed-ssh proxy pods (created dynamically by the operator at runtime, not by this chart) run
with added `SYS_ADMIN`/`SYS_PTRACE` capabilities so each SSH session can `nsenter` into the
target node's real mount/net/ipc/uts namespaces — they deliberately do *not* use
`hostIPC`/`hostNetwork`/`privileged: true` (see `managed_ssh.rs`'s module docs for why). They
*do* use `hostPID: true`, unlike the other three host-namespace flags: `setns(CLONE_NEWPID)` can
only move to a descendant PID namespace, never an ancestor like the host's, so per-session
`nsenter --pid` is fundamentally impossible from a pod whose own PID namespace isn't already the
host's — there's no capability-scoped workaround for this one. `SYS_ADMIN`/`hostPID` still aren't
permitted under the `restricted` or `baseline` Pod Security Standards, only `privileged`, so the
operator's namespace needs that label, e.g.:

```sh
kubectl label namespace ansible-system pod-security.kubernetes.io/enforce=privileged
```

### SELinux-enforcing nodes

Proxy pods also set `securityContext.seLinuxOptions.type: spc_t` ("super-privileged
container"). Joining the host's mount namespace via nsenter does not change a process's own
SELinux label — it stays whatever the container runtime assigned (typically `container_t`),
which is denied write access to almost all host filesystem paths regardless of Unix
permissions or capabilities. `spc_t` is the same label `privileged: true` pods and
node-debugging tools (e.g. `oc debug node/...`) get, and is what actually allows nsenter'd
processes to touch the host filesystem. This is a no-op on non-SELinux nodes.

## Regenerating the bundled CRDs

The CRD manifests under `crds/` are **not templated** — they're a static snapshot generated from
the operator binary itself, matching Helm's convention that `crds/` is install-only (not
upgraded automatically on `helm upgrade`; see the [Helm docs on CRDs](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/)).

After changing any `#[derive(CustomResource)]` type in the Rust source, regenerate them:

```sh
cargo build --release
./target/release/ansible-operator crds > /tmp/all-crds.yaml
csplit -z -f /tmp/crd- /tmp/all-crds.yaml '/^---$/' '{*}'
for f in /tmp/crd-*; do
  name=$(grep -m1 "^  name:" "$f" | awk '{print $2}')
  sed -i '/^---$/d' "$f"
  cp "$f" "chart/crds/${name}.yaml"
done
rm -f /tmp/crd-* /tmp/all-crds.yaml
```

Since `crds/` isn't updated by `helm upgrade`, apply regenerated CRDs manually when they change:

```sh
kubectl apply -f chart/crds/
```
