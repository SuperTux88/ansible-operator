# ansible-operator — agent notes

Opinionated Kubernetes operator that runs Ansible playbooks against cluster
nodes (via ephemeral **managed-ssh proxy pods**) or arbitrary external hosts
(via `StaticInventory` + a BYO SSH key). Inspired by Rancher's
system-upgrade-controller. Rust, built on `kube-rs` 3.x. Single binary, **three**
controllers running concurrently in `main.rs` via `tokio::join!`
(`playbookplancontroller`, `clusterinventorycontroller`, `nodeaccesspolicycontroller`).

> This operator is a **cluster-privileged, node-root primitive**. Before touching
> anything under `playbookplancontroller/` (especially `managed_ssh.rs`,
> `node_access.rs`, `ca.rs`) read `THREAT_MODEL.md` — it is the source of truth for
> the security model. The invariants in the next section are load-bearing.

## Security invariants — do NOT regress without an explicit instruction

These are `THREAT_MODEL.md` §7 (INV-1…INV-7), enforced by unit tests. They are the
whole point of the design. If a change would weaken one, stop and surface it; do not
"simplify" or "clean up" past them unless the user explicitly asks.

- **INV-1 — Fail-closed selectors.** `selector_matches_fail_closed` (`nodeselector.rs`)
  treats an *empty* selector as matching **nothing**; no matching `NodeAccessPolicy`
  ⇒ zero allowed nodes. (Opposite default from `selector_matches`/`node_matches`.)
- **INV-2 — Enforcement is intersection-only.** `node_access::enforce` may only *remove*
  hosts from managed-ssh groups, never add/substitute; `Ssh`/StaticInventory groups pass
  through untouched.
- **INV-3 — Enforcement runs before proxy infra.** NAP clamping happens at inventory
  resolve time (reconcile "step 0b"), on **every** reconcile, before any proxy pod/Secret/
  NetworkPolicy is created.
- **INV-4 — Cross-run isolation is at the cert layer.** Each proxy pod's
  `AuthorizedPrincipalsFile` lists **only its own run's execution hash** (`build_secret`) —
  never `root`, never a wildcard. The client cert carries that hash as a principal. The
  per-run `NetworkPolicy` is defense-in-depth on top, not the primary control.
- **INV-5 — Node set is authoritative & live.** The allow-set is a **live** Node read in
  `enforce`, never a cached one.
- **INV-6 — CA private key never leaves the operator process.** Generated in memory at
  startup (`ca.rs`, `CertificateAuthority::generate` in `main.rs`), never persisted to a
  Secret/etcd, never logged, never in a workspace Secret or the execution hash. A restart
  rotates it.
- **INV-7 — Proxy pods carry both `PLAYBOOKPLAN_HASH` and `PLAYBOOKPLAN_HOST`** so
  cleanup's label-scoped `delete_collection` cannot sweep the ansible Job pod (which lacks
  `_HOST`).

Two recent load-bearing fixes that look like "cleanups" but MUST NOT be reverted:
- **`StrictModes no` in `render_sshd_config`** — required so sshd will read the
  `AuthorizedPrincipalsFile` off the Kubernetes Secret tmpfs mount; without it every
  managed-ssh login fails with `Permission denied (publickey)`. (See its doc comment.)
- **The client-cert Secret is created in the *plan* namespace** (owner-referenced to the
  PlaybookPlan, deleted by name at run completion), because a pod can only mount Secrets
  from its own namespace. Moving it back to the operator namespace breaks any plan whose
  namespace ≠ the operator namespace.

## Layout

```
src/main.rs                          entrypoint (clap `run`/`crds`), tracing, generates the in-memory SSH CA, joins the 3 controllers
src/config.rs                        OperatorConfig (TOML): watch_namespaces (enrolled set) + proxy_image; read once at startup from the mounted ConfigMap
src/utils.rs                         create_or_update helper, Condition trait, generate_id (k8s-like short ID)
src/v1beta1/
  ca.rs                              ephemeral in-memory SSH CA (Ed25519); signs host + client certs; CERT_VALIDITY = 2h (INV-6)
  resources/                         CRD types (kube::CustomResource)
    playbookplan.rs                  PlaybookPlan: spec, status, Phase (incl. UnauthorizedNamespace)
    cluster_inventory.rs             ClusterInventory: hosts resolved from Node labels → managed-ssh (node-root)
    static_inventory.rs              StaticInventory: literal names/IPs + embedded SSH config (BYO key); no controller/status
    node_access_policy.rs            NodeAccessPolicy: admin-authored namespace→node ceiling (cluster-scoped CRD; enforcement reads all policies)
    generic.rs                       NodeSelectorTerm/SelectorExpression, LabelSelector, GenericMap
  controllers/
    playbookplancontroller/          the big one — see below
    clusterinventorycontroller/      resolves Node → hosts, watches Nodes, writes ClusterInventoryStatus
    nodeaccesspolicycontroller/      writes NodeAccessPolicyStatus (matched namespaces / allowed nodes) for observability; watches ns + nodes
    ansible_inventory.rs             ResolvedInventoryGroup (ManagedSsh | Ssh) + ResolvedHosts; AnsibleInventory trait (get_hosts)
    nodeselector.rs                  node_matches / selector_matches / selector_matches_fail_closed (INV-1)
    reconcile_error.rs               shared ReconcileError (thiserror)
  controllers/playbookplancontroller/
    reconciler.rs                    the reconcile pipeline (below); patch_status via JSON merge patch
    node_access.rs                   NodeAccessPolicy enforcement: fail-closed intersection clamp (INV-2/3/5)
    managed_ssh.rs                   proxy pods (hostPID + nsenter = NODE ROOT), per-run sshd config/certs/principals, NetworkPolicy, cleanup (INV-4/7)
    locking.rs                       per-host Leases (operator ns) for run mutual-exclusion
    job_builder.rs                   builds the one Job per run (volumes, client-cert mount, callback env, node anti-affinity)
    workspace.rs                     renders the per-plan workspace Secret (playbook.yml/inventory.yml/recap plugin/vars), owner-ref'd to the plan
    execution_evaluator.rs           ExecutionHash over playbook + referenced Secrets (excludes the self-rendered workspace Secret)
    callback_output.rs               parses the recap the callback wrote to the pod termination message
    triggers.rs                      cron schedule eval (evaluate_schedule / forecast_next_run), timezone-aware
    status.rs                        folds Job/host outcomes into PlaybookPlanStatus conditions
    paths.rs                         shared mount-path conventions between workspace/inventory_renderer/job_builder
  ansible/
    playbook_renderer.rs             round-trips spec.template.playbook YAML (validation)
    inventory_renderer.rs            ResolvedInventoryGroup → Ansible YAML inventory (managed-ssh: proxy IP + HostKeyAlias; ssh: BYO key)
    ansible_operator_recap.py        Ansible callback plugin: writes per-host recap to /dev/termination-log
  labels.rs                          PLAYBOOKPLAN_NAME / _HASH / _HOST label keys
```

## Core reconcile flow (playbookplancontroller/reconciler.rs)

Level-triggered / idempotent "ensure" style — every step re-derives what's needed from
observed cluster state; there is no persisted "current step". One `PlaybookPlan` fans out
into **one Kubernetes Job per run** (targeting that run's hosts), plus **one managed-ssh
proxy pod per targeted ClusterInventory host** in the operator namespace.

1. **Enrollment guard (R1).** If the plan's namespace isn't in the enrolled set
   (`config.rs`: operator ns ∪ `watch_namespaces`), refuse with `Phase::UnauthorizedNamespace`
   and `await_change` — before any Secret/Job call (the operator holds no Secret/Job RBAC
   outside the enrolled set).
2. **Step 0 — resolve inventory.** `resolve_inventory` → `Vec<ResolvedInventoryGroup>`
   (`ClusterInventory` ⇒ `ManagedSsh`, `StaticInventory` ⇒ `Ssh`), preserving which resource
   each group came from.
3. **Step 0b — NodeAccessPolicy enforcement (INV-2/3/5).** `node_access::enforce` clamps
   managed-ssh nodes to the fail-closed intersection of the plan namespace's allowed nodes;
   `warn!`s excluded nodes; sets `status.eligible_hosts`.
4. **Execution hash.** `ExecutionHash` over the playbook text + contents of every referenced
   Secret (variables + files), order-insensitive; deliberately **excludes** the workspace
   Secret (its content — proxy IPs — legitimately changes each run). Hash change ⇒
   `Phase::Pending`, reset `retry_count`, clear `last_triggered_run`.
5. **Step 1 — schedule + outdated hosts.** `triggers::evaluate_schedule` in the plan's
   timezone within a 15s window; `hosts_to_trigger` = outdated hosts (`OneShot`) or all hosts
   (`Recurring`).
6. **`try_start_run` (steps 2–5)** when eligible: acquire per-host **Leases** (`locking.rs`),
   ensure **managed-ssh proxy infra** is Ready (`managed_ssh::ensure_proxy_infra`: proxy
   pods + per-host Secrets + NetworkPolicy in the operator ns, client-cert Secret in the plan
   ns), render/refresh the **workspace Secret** with the live proxy pod IPs, then ensure the
   **one Job** exists (`spawn_ansible_job`: list by hash label, adopt an active Job or create
   the next `retry_count`-numbered one).
7. **`advance_applying_run` (steps 6–7)** once the Job is terminal: parse the per-host recap
   from the pod's **termination message** (`callback_output.rs`, written by the callback
   plugin — not from logs, no `pods/log` access), record host outcomes, `cleanup_proxy_infra`,
   release Leases, set the terminal `Phase` (or reschedule for `Recurring`).
8. **`patch_status`** — JSON **merge patch** (not `replace_status`); many async steps pass
   between read and write, so a version-checked PUT would routinely 409.

Requeue is dynamic: 3600s default, tightened to "time until next scheduled run" / 15s
(Job-polling) / 5s (waiting on proxy readiness) as appropriate.

### managed-ssh (the node-root path)

A `ClusterInventory` host is reached by scheduling an ephemeral **proxy pod onto that node**
(`hostPID: true`, host `/proc` bind-mount, `CAP_SYS_ADMIN`+`CAP_SYS_PTRACE`, SELinux `spc_t`);
every SSH session is wrapped in `nsenter` into the host namespaces (`enter-host.sh`). So a
managed-ssh session is **root on the node** — that is the feature, and the reason
`NodeAccessPolicy` exists. Certs are minted per run from the in-memory CA; cross-run isolation
is the per-run `AuthorizedPrincipalsFile` hash principal (INV-4). See `managed_ssh.rs` doc
comments (they encode hard-won runtime facts: BusyBox `nsenter` short-option quirks, the sftp
`ForceCommand` trick, `StrictModes no`, why `hostPID` can't be joined per-session).

### Execution modes (`ExecutionMode`)

- `OneShot` (default): only outdated hosts run; once every host is current, `Succeeded`/`Failed`
  and it goes quiet until the hash changes.
- `Recurring`: *all* hosts run every schedule tick; reschedules via `forecast_next_run` back to
  `Phase::Scheduled`.

### Job naming and idempotency

Job name is `apply-{plan}-{shortid}-{retry_count}` where `shortid = generate_id(execution_hash)`.
`retry_count` is in the name because the hash alone is unchanged between retries of an identical
spec. Dedup is a fresh `list()` by the run's `PLAYBOOKPLAN_HASH` label plus adopt-newest-active
(`newest_active_job`), not an owner-based get — the reflector-cached `phase` lags this
controller's own writes, so a cache read can't prevent duplicate creates. Per-node **Leases**
give run mutual exclusion.

### Secret / Node change triggers

`.watches(secrets_api, …, mappers::secret_to_playbookplans(…))` re-triggers a plan when a
referenced Secret changes — but Secret/Job watches are set up **per enrolled namespace**, not
cluster-wide (the operator's `secrets`/`jobs` RBAC is scoped there; a cluster-wide `Api::all`
watch would 403). `clusterinventorycontroller` has the Node → ClusterInventory equivalent
(`mappers::node_to_inventories`); `nodeaccesspolicycontroller` recomputes policy status on any
namespace/node change.

## Enrolled namespaces (R1)

The operator only reads/writes Secrets and creates Jobs in **enrolled** namespaces = its own
namespace ∪ the chart's `watchNamespaces`, granted via a per-namespace `Role`/`RoleBinding`
(the `ClusterRole` has no `secrets`/`jobs`/`pods`). Config is read once at startup from the
mounted ConfigMap; a change rolls the pod via `checksum/config` (no hot-reload). A plan in a
non-enrolled namespace is fail-closed to `UnauthorizedNamespace`. The operator can **read and
delete** Secrets in every enrolled namespace, so operators should enroll only namespaces
dedicated to Ansible ops (see `THREAT_MODEL.md` §6 / T-INFO-1).

## Known rough edges / things to know before touching related code

- **Status writes are JSON merge patches** in all three controllers (`patch_status` →
  `Patch::Merge({"status": …})`), never `Api::replace_status` (a version-checked PUT that would
  routinely 409 across a reconcile's many async steps). Only the `.status` subresource is sent.
- `examples/v1beta1/*.yaml` is the canonical CRD shape; `examples/ssh.yaml` (top-level) is the
  only remaining older example — prefer `v1beta1/` when writing docs/examples.
- Deliberate `.unwrap()`/`.expect()` style: preconditions the apiserver genuinely guarantees are
  unwrapped; only things this operator must guarantee (namespace/name/generation/uid on the
  primary object) go through `ReconcileError::PreconditionFailed`. Match this — don't blanket-add
  error plumbing to apiserver-guaranteed invariants, and don't unwrap things the operator owns.
- `FilesSource::Other` round-trips arbitrary JSON/YAML through a real
  `k8s_openapi::…::Volume` via `serde_json` (any volume type without hand-modeling); errors
  surface per-item as `Result`, not a panic.
- `ansible/playbook_renderer.rs` re-parses+re-serializes the playbook mostly as validation.
- The `NodeAccessPolicy` CRD is *cluster-scoped* — creating one requires cluster RBAC, which is
  what makes it an admin (not tenant) control. Enforcement reads **every** policy in the cluster;
  a namespace's allow-set is the union across all policies whose `namespaceSelector` matches it.

## User & operator documentation (`docs/` mdBook) — keep in sync with the code

End-user and cluster-operator docs are an **mdBook** under `docs/` (`docs/book.toml`, chapters in
`docs/src/*.md`, TOC in `docs/src/SUMMARY.md`; `just docs` builds it to the git-ignored `docs/book/`).
This is the narrative guide; rustdoc (`just apidoc`) is the separate API reference for the code. Two
chapters: `docs/src/running-playbooks/` (users authoring PlaybookPlans/inventories) and
`docs/src/cluster-operators/` (admins installing/securing the operator). The guide is **part of the
change surface** — a behaviour/API/security change is not done until the matching page is updated. Map:

- CRD field / default / enum change → the page for that resource under `running-playbooks/`:
  `playbook-plans.md` (PlaybookPlan), `cluster-nodes.md` (ClusterInventory), `external-hosts.md`
  (StaticInventory), `variables-and-files.md` (`template.variables`/`files`), `scheduling-and-modes.md`
  (`schedule`/`mode`/hash), `results-and-troubleshooting.md` (status/phases/outcomes); or
  `cluster-operators/node-access-policies.md` (NodeAccessPolicy).
- Chart / deploy / RBAC / PSA / SELinux / proxy-image / `watchNamespaces` change → `cluster-operators/deployment.md`.
- Threat-model / invariant change → `cluster-operators/security.md` (a **summary**; `THREAT_MODEL.md`
  stays the source of truth — the page says so, so update both and keep them consistent).
- Secret-key conventions the user must match (`variables.yaml`; StaticInventory `id_rsa`/`known_hosts`;
  file mount paths under `/run/ansible-operator/files/<name>`) live in `variables-and-files.md` /
  `external-hosts.md` — re-verify against `workspace.rs`/`job_builder.rs`/`inventory_renderer.rs`/`paths.rs`
  if you touch those.

Conventions: the guide is **prose** — refer to CRD types as inline code (`` `PlaybookPlan` ``) and
defer exhaustive field lists to the API reference (`ansible-operator crds` / `just apidoc`), don't
restate whole field tables. Cross-references between pages are **relative markdown links**
(`./playbook-plans.md`, `../cluster-operators/deployment.md#enrolled-namespaces`); heading anchors are
mdBook slugs (lowercase, punctuation stripped, spaces→`-`), so a link into `## The proxy image`
becomes `#the-proxy-image`. Verify with `just docs`; adding/removing a page also needs a `SUMMARY.md`
entry (a page missing from `SUMMARY.md` is not rendered). mdBook has no built-in broken-link check, so
eyeball new cross-page links (or run the `mdbook-linkcheck` backend if installed).

## Testing & workflow

- `cargo test` — unit tests colocated in `#[cfg(test)] mod tests` at the bottom of each file
  (no `tests/` dir); follow this convention. Prefer extracting a small pure function (as
  `execution_evaluator`, `triggers`, `status`, `nodeselector`, `node_access::clamp_*`,
  `job_builder::extract_file_volumes` do) over testing through the full `reconcile()`.
- `managed_ssh::container_tests` is an `#[ignore]`d testcontainers test that boots the real
  proxy sshd image and asserts per-run cert isolation (INV-4). It needs a Docker/Podman socket
  and an `ssh` client; it validates cert *logic*, not the on-cluster Secret-mount permissions
  (that's what the `StrictModes no` unit assertion guards — see the test's doc comment).
- `cargo clippy` is clean and there's no `clippy.toml`; keep it clean (a scoped
  `#[allow(clippy::too_many_arguments)]` on `ensure_proxy_infra` is the only deliberate
  exception). Run `cargo build` + `cargo test` + `cargo clippy` before proposing changes — and
  the guide build (`just docs`) if you touched `docs/` or user-facing behaviour/CRDs/chart.
  `just check` runs everything (build + test + clippy + guide + apidoc); see the `Justfile` for recipes.
- `./ansible-operator crds` dumps all **four** CRDs (PlaybookPlan, ClusterInventory,
  StaticInventory, NodeAccessPolicy) — check this path after changing any `CustomResource` type.
- The chart renders `managedSsh.proxyImage` and `watchNamespaces` into the operator ConfigMap;
  `helm template ./chart -s templates/configmap.yaml` (and `templates/role.yaml`) is the quick
  way to sanity-check chart wiring.
- CI (`.github/workflows/build-test-push.yml`): `cargo test` + `cargo build --release`, then a
  Containerfile distroless image (binary copied in, no cargo build inside the image).
- `.agents/skills/` is a vendored skill pack (rust-skills), unrelated to this project's domain —
  not something to modify as part of feature work.
```
