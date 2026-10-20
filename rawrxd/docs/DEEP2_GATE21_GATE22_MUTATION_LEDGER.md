# Deep2 Gate 21/22 Mutation Ledger

This document defines the source-only safety boundary for TPS mutation work. It does not
authorize a model benchmark and does not promote a performance candidate.

## Gate 21: immutable baseline

The baseline contains an explicit file scope. Every entry records a canonical repository-relative
path, byte length, and SHA-256 content digest. The snapshot is written outside the accepted
workspace and is verified against the same inventory before mutation begins. Baseline metadata is
create-once; the keeper refuses to overwrite it.

The baseline inventory digest covers the canonical JSON representation of the sorted file entries.
This prevents changing the metadata file itself from changing what the baseline means.

## Gate 22: disposable fault isolation

`deep2_gatekeeper.ps1 -Action FaultTest` creates a temporary fixture and runs nine independent
failure checks:

1. changed workspace file
2. unexpected workspace file
3. missing workspace file
4. unexpected snapshot file
5. corrupt snapshot contents
6. missing snapshot file
7. malformed baseline JSON
8. invalid baseline schema or inventory digest
9. orphaned recovery transaction

The test also verifies successful recovery and deletes only its own temporary fixture. It never
receives a production repository path as a fault-injection target.

## Recovery transaction

Restore first copies the immutable snapshot into a temporary staging directory and verifies the
staging inventory. It then records `APPLYING` before touching the workspace, copies the staged
files, verifies the workspace, and records `COMPLETE`. A later `Recover` action replays any
transaction that stopped at `APPLYING`.

## MutationLedger

The ledger is append-only JSONL with a separate trusted head file. A record is canonicalized as
deterministic UTF-8 JSON. For record bytes `R` and length `L`, the chain uses:

```text
H_i = SHA256(raw(H_(i-1)) || little_endian_uint64(L) || R)
```

The first previous hash is 32 zero bytes. Every ledger line stores the sequence number,
previous hash, record length, canonical record bytes, and resulting hash. Verification rejects
blank lines, sequence gaps, previous-hash changes, byte-length mismatches, non-canonical records,
hash mismatches, and a missing or divergent head file.

## Promotion rule

An accepted benchmark is not a promotion. The mutation gate restores all candidates by default.
Only an explicit `-Promote` invocation can leave the candidate live, and that event is recorded
separately. The current R9700/Vulkan benchmark pause remains enforced by the gate's separate
`RAWRXD_D2_BENCHMARK_AUTHORIZATION=EXPLICIT_USER_RESUME` check.
