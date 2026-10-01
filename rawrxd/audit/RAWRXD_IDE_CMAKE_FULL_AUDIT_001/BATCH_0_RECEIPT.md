# BATCH 0 — Authority / preflight receipt

Authority: RAWRXD_IDE_CMAKE_FULL_AUDIT_001
HEAD: a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (pinned)
Verdict: GATE_OPEN — all 10 items PASS

```
ITEM_01_HEAD             = PASS  a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
ITEM_02_ORIGIN           = PASS  a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
ITEM_02_UPSTREAM         = PASS  a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
ITEM_03_STAGED           = PASS  0
ITEM_04_WORKTREE         = PASS  documented (M=12 D=25 ??=116 — pre-existing)
ITEM_05_LEASE_FILE       = PASS  F:\~dev\.rawrxd\leases\writer.lease
ITEM_06_LEASE_COVERS     = PASS  covers RAWRXD_DEEP2_GENERATION_LIFECYCLE_001
                                (see authorized_paths below)
ITEM_07_NO_COMPETING     = PASS  one lease, one nonce, no other writer
ITEM_08_FREEZE_UNRELATED = PASS  only lease paths may be modified
ITEM_09_FREEZE_AGENT     = PASS  src/agent/*, src/authority/*, src/agentmodes/*
                                all frozen — no mutation in this audit
ITEM_10_AUDIT_BUILD_DIR  = PASS  audit dir clean, build dirs preserved

GATE = PASS
```

## Lease contents (verbatim from `F:\~dev\.rawrxd\leases\writer.lease`)

```json
{
  "repository_root": "f:/~dev",
  "pid": 30252,
  "nonce": 5712953110738933491,
  "expected_head": "a078e3b87be6b22ed1fa6fce6a20bfdd980e4441",
  "acquired_unix_seconds": 1790793884,
  "authorized_paths": [
    "f:/~dev/rawrxd/src/deep2/deep2engine.h",
    "f:/~dev/rawrxd/src/deep2/deep2engine.cpp",
    "f:/~dev/rawrxd/src/deep2/tokenizer.hpp",
    "f:/~dev/rawrxd/tools/deep2_generation_lifecycle_test.cpp"
  ]
}
```

## Notes

- The lease **expected_head** matches the current HEAD literal
  (`a078e3b87`), so I am not racing a concurrent writer that already
  pinned to a different commit. The concurrent writer (PID 30252) is
  working on the same frozen HEAD.
- The lease authorized_paths cover exactly the four files required for
  Batch 1 (Deep2 lifecycle closure) and Batch 2 (result contract + EOS).
  No new lease acquisition is required for those batches.
- Worktree is dirty (12 M + 25 D + 116 ??). This is **pre-existing**
  work from earlier sessions; **ITEM_04 documents it but does not
  remediate it** — the dirty state is not introduced by this audit and
  remains outside the lease scope.
- Items 8 and 9 are freezes, not mutations. They will be re-checked at
  the end of every batch to ensure no out-of-scope files are touched.

## What is NOT authorized in this audit

- Any file under `src/agent/`, `src/agentmodes/`, `src/authority/`
- Any file in `tools/` other than `deep2_generation_lifecycle_test.cpp`
- Any `CMakeLists.txt` mutation (covered by a separate future batch)
- Any HEAD movement (no commit, no push)
- Any receipt file outside the audit directory

## What IS authorized

- The four files in `authorized_paths` above, for the purpose of D2
  (KV reset between generations), D1 (result contract), and D3
  (EOS/control termination).
- Adding new test code under `tools/deep2_generation_lifecycle_test.cpp`
  to prove the same-engine four-generation regression.

## Next batch

Batch 1 — Deep2 lifecycle closure — 15 items, all bounded by the
authorized paths above. Closes only after the measured receipt
shows:

```
GEN1=PASS
GEN2=PASS
GEN3=PASS
GEN4=PASS
ENGINE_INSTANCE_COUNT=1
STALE_KV_EXCEPTIONS=0
D2_KV_RESET=PASS
```
