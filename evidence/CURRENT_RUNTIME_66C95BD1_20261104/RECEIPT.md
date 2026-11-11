# Current Repair Candidate Runtime Receipt

## Identity

- Previous frozen reference preserved at `F:/rawrxd/evidence/FROZEN_2FB9_REFERENCE_20261104/RawrXD-Win32IDE-Native.exe`
- Previous reference SHA256: `2FB9E1B7351EF67AA4876318B6773DBD11AF31D0552ACFC90E61FD080F18A029`
- Repair candidate: `F:/rawrxd/build_repair_candidate/bin/RawrXD-Win32IDE-Native.exe`
- Repair candidate SHA256: `66C95BD1CC2D1855660FA1B88C818232AE977D414D579F843E796240D55D3844`
- Repair candidate size: `6111232` bytes
- Source HEAD at test start: `bbb26a9e2b230174d06747fa7b6abfc5fad412fb`

## Changes under test

`Win32IDE_lifecycle.cpp` adds keyboard tab-stop behavior to the native editor and restores editor focus after tab switching. The source change creates a new binary identity; evidence for `2FB9...` does not transfer.

## Build and regression

- Native build: `PASS` (`cmake --build build_repair_candidate --config Release --target RawrXD-Win32IDE-Native -j 4`)
- CTest: `27 PASS / 1 SKIP / 0 FAIL` (28 tests total)
- Skipped test: `deep2_h11_prefill_parity`

## Runtime gates

- T05: prior `2FB9...` behavioral receipt remains valid for that frozen binary only.
- T10: `NOT_VERIFIED` on this candidate; no reliable GUI unsaved-buffer fixture was captured.
- T080: `NOT_VERIFIED` on this candidate.
- T15 autonomous: `OPEN`; no model-originated edit receipt.
- T18/T19/T24/T25: `OPEN/HELD`.

## Disposition

This is a repair candidate, not a certified or promoted product. `PROMOTE=0`, `CERTIFIED=0`.
