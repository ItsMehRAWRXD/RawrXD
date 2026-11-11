# Current Candidate Runtime Receipt

```ini
SOURCE_COMMIT=bbb26a9e2b230174d06747fa7b6abfc5fad412fb
CANDIDATE_PATH=F:\\rawrxd\\build_repair_candidate\\bin\\RawrXD-Win32IDE-Native.exe
CANDIDATE_SIZE=6111232
CANDIDATE_SHA256=2FB9E1B7351EF67AA4876318B6773DBD11AF31D0552ACFC90E61FD080F18A029
```

## Headless runtime

- Native target build: PASS
- CTest: 27 PASS / 1 SKIP / 0 FAIL
- Skipped test: `deep2_h11_prefill_parity`
- CTest total time: 4.37 seconds

## Evidence binding

The physical T05 UI sequence in
`evidence/T05_RUNTIME_CURRENT_D7101D09_20261104/RECEIPT.md` belongs to the
previous executable hash `D7101D09...` and is historical for this candidate.
It must be rerun before T05 can be marked PASS for this executable.

Current-binary GUI gates remain open: T05, T10, T080 row/navigation, T15
autonomous dispatch, T18/T19 soak, and independent T25 review.
