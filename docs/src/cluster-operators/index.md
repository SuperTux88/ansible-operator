# For cluster operators

This chapter is for the **cluster administrators** who install, secure, and run the operator, as
opposed to the tenants who author playbooks (that is [Running playbooks](../running-playbooks/index.md)).
Read it before installing: the operator is a **cluster-privileged, node-root** component, and several
of its controls are fail-closed by default and must be opened deliberately — namespace enrollment and
node access.

## Your responsibilities

- **Install** the Helm chart into a dedicated, `privileged`-labelled namespace, and pin the
  managed-SSH proxy image. → [Deployment](./deployment.md)
- **Configure your admission policies** for the exceptions the operator needs, and only those. →
  [Admission policies](./admission-policies.md)
- **Enroll** the tenant namespaces that are allowed to run playbooks (fail-closed: a plan in an
  un-enrolled namespace is refused). → [Deployment → enrolled namespaces](./deployment.md#enrolled-namespaces)
- **Grant node access** with `NodeAccessPolicy` resources (fail-closed: no policy means a namespace
  can reach no Nodes). → [Node access policies](./node-access-policies.md)
- **Understand the trust boundaries** you take on and the invariants that hold them. →
  [Security model](./security.md)

## Source of truth

This chapter is an operator-facing summary. The full analysis — threats, mitigations, and the
numbered invariants (INV-1…INV-7) — lives in the repository's `THREAT_MODEL.md`. If this guide and
`THREAT_MODEL.md` disagree, `THREAT_MODEL.md` is authoritative; report the discrepancy as a
documentation bug.

## In this chapter

- [Deployment](./deployment.md) — install, namespaces, Pod Security Admission, SELinux, the proxy image, config
- [Admission policies](./admission-policies.md) — the policy exceptions to grant, and the ones not to grant
- [Security model](./security.md) — node-root, the ephemeral CA, per-run isolation, and the blast radius you accept
- [Node access policies](./node-access-policies.md) — capping which Nodes a namespace may reach
