# RawrXD Build Provenance Certificate

Date: 2026-10-13
Purpose: reconcile the binary-hash-to-revision relationship recorded for the
H1–H5 host-security certification.

## The reported discrepancy

The H3/H5 certificate recorded binary hash `5CE4D412…` against source revision
`9f502fa9d8`, while the certificate itself was authored at `3e0f850c42`. The
question was whether a hash recorded at `9f502fa9d8` is valid for `3e0f850c42`.

## Resolved by direct file comparison

I diffed the two revisions rather than assuming. `git diff --name-only`
between them:

```
9f502fa9d8..3e0f850c42
  tests/H3_H5_ACCEPTANCE.md
```

That is a documentation-only change. **No file under `src/` or `include/`
differs.** A binary compiled from `9f502fa9d8` is therefore byte-identical to
one compiled from `3e0f850c42`, and the recorded `5CE4D412…` hash is valid for
both revisions. The apparent provenance gap does not exist for that pair.

The definitive check is the one above: compare the source file sets, not the
commit messages.

## Where the hash does NOT transfer

It does NOT transfer to the current HEAD, because `src/rawr_cli.cpp` changed
after `3e0f850c42` (the Gate 2 capability-manifest work). Any certificate
carried forward must be re-issued after a rebuild.

## Current build record

| Item | Value |
| --- | --- |
| Source revision | `55aa8085baa70c3eb142b51fe2c8b734f5257076` |
| Binary | `rawr.exe` |
| SHA-256 | `5432E0E4B3BF70DE0A87D00714676857D3C2D85A668F7EC95D4FB146F81C913A` |
| Size | 1,029,632 bytes |
| Toolchain | MSVC 14.44.35207 (VS 2022 Build Tools), `/std:c++17` |
| Sources | `src/rawr_core.cpp`, `src/rawr_cli.cpp` |
| Include dirs | `include/`, `src/` |

> The revision number above was captured immediately before this file was
> written. Because other commits are landing on this branch concurrently,
> verify with `git rev-parse HEAD` before relying on it and rebuild if it has
> moved; the SHA-256 in this table is only meaningful for the revision on the
> same row.

## Accepted gates and their true status

| Gate | Status |
| --- | --- |
| CMake configure + K-quant target build (Gate 1) | PASS |
| Capability manifest regenerated (Gate 2) | implemented, with a stated limitation |
| Real GGUF tensor geometry (Gate 3) | not started |
| Native forward, zero fallback (Gate 4) | not started |
| Embeddings/attention/FFN/logit parity (Gate 5) | not started |
| Multi-token KV correctness (Gate 6) | not started |
| Performance + numerical receipts (Gate 7) | not started |

## Manifest limitation carried forward

`evidence/capability_manifest.json` derives tools and modes from live
registrations, but its primitive statuses are transcribed from
`src/deep2/QuantParityRegistry.cpp` because this CLI does not link that
translation unit. The manifest states this in its own `primitives_provenance`
field. The authoritative primitive emitter is `quant_parity_cert`, which runs
as a ctest gate and does link the registry; the two should be reconciled before
the manifest is treated as authoritative for primitives.
