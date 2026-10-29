# ansible-operator — agent notes

Kubernetes operator (Rust, kube-rs) that runs Ansible playbooks against cluster Nodes through
ephemeral **managed-ssh proxy pods** (`ClusterInventory`) or external hosts with a BYO SSH key
(`StaticInventory`). One binary, three controllers joined in `src/main.rs`: `playbookplancontroller`
(the big one), `clusterinventorycontroller`, `nodeaccesspolicycontroller`. Modules carry their own
`//!` docs — read those for the details; this file only lists what is easy to break by accident.

## Security — read `THREAT_MODEL.md` first

A managed-ssh session is **root on the node**. Before touching `managed_ssh.rs`, `node_access.rs`,
`node_labels.rs`, `ca.rs` or anything that decides which Nodes a run reaches, read
`THREAT_MODEL.md`. Its §7 invariants are enforced by unit tests; do not weaken one without an
explicit instruction — stop and surface it instead:

- **INV-1** `selector_matches_fail_closed`: an empty selector / no matching policy ⇒ zero nodes.
- **INV-2** `node_access::enforce` only removes managed-ssh hosts; `Ssh` groups pass through.
- **INV-3/3b** Clamping runs on every reconcile before any proxy infra, and
  `ensure_infra_and_launch` re-authorizes the set it is about to render, never one from a record.
- **INV-4** A proxy's `AuthorizedPrincipalsFile` lists only its own run ID (never `root`/wildcard).
- **INV-5** The allow-set comes from a **live** Node read, never the reflector cache.
- **INV-6** The CA key is in memory only: never persisted, logged, or hashed.
- **INV-7** Proxy pods carry both `PLAYBOOKPLAN_HASH` and `PLAYBOOKPLAN_HOST`.
- **INV-8** The only Node writes are `dependency_keys::label_key` labels from the plan's own ns/name.

Looks like cleanup, is not: `StrictModes no` in `render_sshd_config`, and the client-cert Secret
living in the *plan* namespace (see `managed_ssh.rs`).

The reconcile pipeline is described in the module doc of `playbookplancontroller/reconciler.rs`;
the `Play` record protocol in `play_history.rs`.

## Decisions that are easy to undo by accident

Each is explained at the code it names; read that before changing it.

- Plan status is a JSON **merge patch**; `Play` writes go through `replace_status` with a
  `resourceVersion` precondition. Different questions — don't unify them.
- The complete result reaches the plan **before** the `Play` is acknowledged or prunable.
- `activeRun` is mirrored onto the plan **before** Leases or proxy pods are taken.
- No snapshots of plan spec / Job blueprint in `Play`; `preparationFingerprint` covers them.
- The run ID is recorded, not derived (`reconciler::run_id`); `select_job` never adopts a Job and
  numbers past every Job *and* retained `Play` of the plan.
- `locking::renew_locks`: `Lost` ≠ `Unconfirmed`; only `Lost` may abandon a run.
- Schedule windows are judged from records (`window_taken_by_a_record`), per host; refunds
  (`returns_its_attempt`) and the window count must use the same predicate. `retryGeneration` must
  not be replaced by the retry token, a timestamp or a run-number cutoff.
- `spec.suspend` is decided before the inventory read (`resolve_unlaunched_before_inputs`).
- Node readiness gate and the unreachable-host refund are a matched pair (`node_readiness.rs`).
- Node labels: status first, labels after; only on a real value change (`node_labels.rs`).
- Unsynced `Store`s answer wrongly rather than failing: the initial cache waits are bounded and
  fatal, and the controllers are `join!`ed, not spawned.
- Raw cron strings go only through `triggers::Schedule::parse`; schedule evaluation stays total.
- New `watcher` streams use `watch_stream::restarting_watcher`, not `.default_backoff()`.
- The completion-marker task name is duplicated in `playbook_renderer.rs` and
  `ansible_operator_recap.py`, pinned by a test.
- `unwrap`/`expect` only for apiserver-guaranteed invariants; what the operator must guarantee goes
  through `ReconcileError::PreconditionFailed`.

## User guide (`docs/` mdBook) is part of the change surface

A behaviour, CRD, chart or security change is not done until its page is updated:
`docs/src/running-playbooks/` (one page per resource/topic) and `docs/src/cluster-operators/`
(deployment, NodeAccessPolicies, security). `security.md` summarises `THREAT_MODEL.md`; update
both. Prose, not field tables; relative links with mdBook slug anchors; new pages need a
`SUMMARY.md` entry. `examples/v1beta1/*.yaml` is the canonical CRD shape.

## Workflow

- `just check` = build + Rust and Python tests + clippy + guide + apidoc; run it before proposing
  changes. `just` lists the other recipes.
- Rust unit tests live in `#[cfg(test)] mod tests` in each file; prefer extracting a small pure
  function over testing through `reconcile()`.
- `tests/python/` is stdlib `unittest` with no dependencies; keep it that way.
- Clippy stays clean; the only allowed exception is `too_many_arguments` on `ensure_proxy_infra`.
- After changing a `CustomResource` type: `just crds` (all five CRDs), then `just generate-crds`.
  CRD doc comments are copied verbatim into Helm templates, so never write `{{ … }}` in one;
  check with `helm template ./chart | grep`.
- `managed_ssh::container_tests` is `#[ignore]`d and needs a container socket + `ssh`.
