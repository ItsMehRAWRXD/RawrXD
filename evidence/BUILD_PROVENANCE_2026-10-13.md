# RawrXD Build Provenance Certificate

Date: 2026-10-13
Purpose: reconcile the binary-hash-to-revision relationship recorded for the
H1–H5 host-security certification.

## The reported discrepancy

The H3/H5 certificate recorded binary hash `5CE4D412…` against source revision
`9f502fa9d8`, while the certificate itself was authored at `3e0f850c42`. The
question was whether a hash recorded at `9f502fa9d8` is valid for `3e0f850c42`.

## Correction: byte-identity is NOT established, and cannot be

I initially concluded that because no source file differs between
`9f502fa9d8` and `3e0f850c42`, the two binaries "are byte-identical". That
stronger claim is not supported and I have withdrawn it. Two independent builds
from the **same** source produce different files:

```
build1  C2E563883A56F7341D02F72CEEBEB645A84EB8A0B01D8F650A2DDB034B5C216C
build2  7AAA51A4D67960CB804D0622CC2A8FF6EDC06748214BA76E016A6D86013D586D
```

Inspecting the PE headers shows why: the linker writes a COFF build timestamp
into every output.

```
b1 : COFF timestamp 2026-10-13T05:27:36Z
b2 : COFF timestamp 2026-10-13T05:27:45Z
```

So byte-identity is unreachable with this toolchain regardless of source state.
What *is* sound is the weaker and still useful claim: **the compiled code is
equivalent** because no source file differs. That is an argument about inputs,
not about output hashes.

### What this means for the certificate

The correct statement is:

> The H3/H5 binary hash `5CE4D412…` was recorded against source revision
> `9f502fa9d8`. That revision and `3e0f850c42` differ only in
> `tests/H3_H5_ACCEPTANCE.md`; nothing under `src/` or `include/` differs, so
> the code compiled from either revision is equivalent. No byte-identity claim
> is made, because this toolchain embeds a build timestamp in every output and
> cannot produce reproducible-byte binaries.

To get genuinely reproducible binaries, the build would need a deterministic
timestamp (`/Brepro` for the linker, or a stripped/normalized build) — this is
a real gap for certificate workflows that compare hashes, and it is listed
below rather than hidden.

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
