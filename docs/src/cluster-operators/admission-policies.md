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
| Disallow privileged containers | no | — |
| Restrict ServiceAccount token automount | no | — |
| Require NetworkPolicies | no | — |

## Where the workloads run

Both exceptions apply to the managed-SSH proxy pods, and only to them. Knowing where each workload
lives is what makes that possible:

- **Proxy pods** are created by the operator in the **operator's own namespace**, never in the
  namespace of the `PlaybookPlan` that triggered the run. They carry the label
  `ansible.cloudbending.dev/component: managed-ssh-proxy`.
- **The operator Deployment** lives in the same namespace and is compliant with both policies.
- **Ansible Jobs** run in the namespace of their `PlaybookPlan` — a tenant namespace, which needs no
  exception at all. They are labelled `ansible.cloudbending.dev/component: playbook`.

Scope both exceptions to that pod label, and to the operator's namespace. That is the narrowest
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

Kubernetes treats the proxy's required `SYS_ADMIN` capability as privilege escalation, so proxy
containers cannot set `allowPrivilegeEscalation: false`. Setting it anyway would be misleading and
is rejected on some runtimes.

Everything else stays enforced:

- The operator container sets `allowPrivilegeEscalation: false` by default.
- Generated Ansible Jobs are compliant as soon as the plan requests it:

  ```yaml
  spec:
    securityContext:
      allowPrivilegeEscalation: false
  ```

  This is per plan rather than a chart-wide setting, because the setting has to be compatible with
  the execution image the plan uses. See
  [Playbook plans](../running-playbooks/playbook-plans.md).

## Controls that need no exception

**Privileged containers.** The proxy pods request individual capabilities and an SELinux type. They
never set `securityContext.privileged: true`.

**ServiceAccount token automount.** The operator ServiceAccount sets
`automountServiceAccountToken: false` and the operator Deployment requests its token explicitly;
proxy pods disable the mount; an Ansible Job only receives a token if its plan sets
`serviceAccountName`. A ServiceAccount named by a plan must comply with your policy on its own.

**Required NetworkPolicies.** Set `networkPolicy.enabled: true`. The chart then creates an egress
policy selecting the operator pod, which satisfies policies that require every workload to be
covered by a NetworkPolicy, and the operator creates the per-run policies for Ansible Jobs and proxy
pods. The rule arrays are environment-specific — see
[Deployment → network policies](./deployment.md#network-policies).
