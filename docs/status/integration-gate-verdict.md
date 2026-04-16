# Integration gate verdict (manager-green → system-wide readiness)

## Snapshot

- **Date**: 2026-04-15
- **Branch**: `feature/tool-ecosystem-unblock-autonomy`
- **Intent**: capture the working state that unblocks “integration gate” progression without committing build artifacts or transient logs.

## Current verdict

- **Manager slice**: **PASS**
  - Speculative stress teardown noise reduced (e.g. `one_loop_policy_violation` no longer dominates logs).
  - Negative-path probes (IPC/security) remain stable.
- **Sandbox integrity**: **PASS**
  - `sandbox_probe` denials are **expected** security boundary assertions.
- **System integration**: **IN PROGRESS**
  - Broader coupling still depends on cross-process manifest negotiation and full environment load.

## Log interpretation rule (for CI readers)

- If you see **`sandbox_probe` denials** and the run ends in **`PASS`** → **security boundary confirmed**.
- If you see **`preexec_broker_hash_mismatch`** through **`unknown_request_id`** and the run ends in **`PASS`** → **negative-path coverage complete; integrity gates functional**.
- Mid-log truncation (e.g. around `network_private_denied`) is **non-diagnostic** if the runner continues into manifest/pre-exec and emits a final **PASS**.

## Repro notes

- Prefer running the minimal orchestrator (offline extension installer + turnkey IDE smoke) and then reading the JSON summary it emits.
- Do not commit build outputs (`build*/`, `.idx`) or transient `logs/*.json` artifacts as part of this snapshot.

