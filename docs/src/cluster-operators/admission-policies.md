# Admission policies

Clusters that enforce workload policies with an admission policy engine (Kyverno, Gatekeeper, or a
comparable tool) need a small, well-scoped set of exceptions for this operator — and, just as
importantly, *no* exception for most controls. This page lists what has to change, and why each
change is permanent or avoidable.

Pod Security Admission itself is covered in [Deployment](./deployment.md#pod-security-admission):
the operator namespace must be labelled `privileged`.

## Summary

| Control | Exception needed | Scope |
| --- | --- | --- |
| Disallow host namespaces | yes, permanent | proxy pods, by label and namespace |
| Disallow privilege escalation | yes, permanent | proxy pods, by label and namespace |
| Disallow privileged containers | yes, permanent | proxy pods, by label and namespace |
| Restrict ServiceAccount token automount | no | — |
| Require NetworkPolicies | no | — |

## Where the workloads run

All three exceptions apply to the managed-SSH proxy pods, and only to them. Knowing where each
workload lives is what makes that possible:

- **Proxy pods** are created by the operator in the **operator's own namespace**, never in the
  namespace of the `PlaybookPlan` that triggered the run. They carry the label
  `ansible.cloudbending.dev/component: managed-ssh-proxy`.
- **The operator Deployment** lives in the same namespace and is compliant with all three policies.
- **Ansible Jobs** run in the namespace of their `PlaybookPlan` — a tenant namespace, which needs no
  exception at all. They are labelled `ansible.cloudbending.dev/component: playbook`.

Scope all three exceptions to that pod label, and to the operator's namespace. That is the narrowest
scope that grants what the proxies need: the policies stay enforced for the operator Deployment and
for anything else running in the same namespace, and the label grants nothing to a pod that carries
it in another namespace. In Kyverno both conditions go into one rule, where they are ANDed:

```yaml
exclude:
  any:
    - resources:
        namespaces:
          - ansible-system
        selector:
          matchLabels:
            ansible.cloudbending.dev/component: managed-ssh-proxy
```

## Host namespaces

Managed-SSH proxy pods run with `hostPID: true`; without it they cannot `nsenter` into the target
Node. This exception is permanent — auditing it instead only produces reports that can never be
acted on.

The proxy pods do **not** set `hostNetwork` or `hostIPC`, so an exception limited to `hostPID` is
sufficient if your policy engine can express that.

## Privilege escalation

Proxy containers are privileged (see [Privileged containers](#privileged-containers)), and
Kubernetes rejects `allowPrivilegeEscalation: false` on a privileged container.

Everything else stays enforced:

- The operator pod meets the `restricted` Pod Security Standard by default, including
  `allowPrivilegeEscalation: false` (see [Workload security
  contexts](./deployment.md#workload-security-contexts)).
- Generated Ansible Jobs are compliant as soon as the plan requests it:

  ```yaml
  spec:
    securityContext:
      allowPrivilegeEscalation: false
  ```

  This is per plan rather than a chart-wide setting, because the setting has to be compatible with
  the execution image the plan uses. See
  [Playbook plans](../running-playbooks/playbook-plans.md).

## Privileged containers

Managed-SSH proxy containers set `securityContext.privileged: true`. A session `nsenter`s into the
Node's namespaces but stays in the proxy pod's cgroup, and for an unprivileged container that cgroup
refuses access to the Node's block devices. Without `privileged`, anything that opens a disk —
`grub-install` in a bootloader package update, `mkfs`, firmware tools — fails with `Operation not
permitted`, even though the session is otherwise `root` on the Node. The exception grants no reach a
session does not already have; see [Security](./security.md#privileges-the-proxy-pods-hold).

Releases up to v1.0.2 did not need this exception. Add it **before** upgrading from one of them:
otherwise the policy engine rejects every proxy pod. Runs against cluster Nodes do not fail but stall
with the summary **"could not prepare run …"** naming the admission error, and retry every tick
while holding their host Leases, so other plans targeting the same Nodes wait as well (see
[Results and troubleshooting](../running-playbooks/results-and-troubleshooting.md)). Once the
exception is in place, the next attempt creates the proxy pods and the runs continue on their own.

## Controls that need no exception

**ServiceAccount token automount.** The operator ServiceAccount sets
`automountServiceAccountToken: false` and the operator Deployment requests its token explicitly;
proxy pods disable the mount; an Ansible Job only receives a token if its plan sets
`serviceAccountName`. A ServiceAccount named by a plan must comply with your policy on its own.

**Required NetworkPolicies.** Set `networkPolicy.enabled: true`. The chart then creates an egress
policy selecting the operator pod, which satisfies policies that require every workload to be
covered by a NetworkPolicy, and the operator creates the per-run policies for Ansible Jobs and proxy
pods. The rule arrays are environment-specific — see
[Deployment → network policies](./deployment.md#network-policies).
