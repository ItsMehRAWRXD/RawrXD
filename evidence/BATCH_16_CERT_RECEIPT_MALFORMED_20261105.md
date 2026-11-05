# Batch 16 — 15 malformed certification receipt blockers

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Audit finding

The end-to-end receipt verifier could crash when `candidate_sha256` was null, numeric or a list because it called `.lower()` unconditionally. It also accepted symlinked receipt JSON files and read evidence in one unbounded allocation. These are certification harness defects, not proof of native IDE product defects.

## Commits

- `b731d953a67346b802c597d5c5306ea2d0bd6c40`: handle malformed hash types without exceptions, reject symlinked receipt JSON, stream evidence hashing in bounded chunks, fail closed on evidence I/O errors.
- `5ff771cc12c6d8c153c7607d05121556590df9b5`: add 15 malformed receipt variants with a positive control.

## Fifteen test variants

01 Null gate identity.
02 Numeric gate identity.
03 Explicit FAIL status.
04 Boolean status.
05 Null candidate hash.
06 Numeric candidate hash.
07 List candidate hash.
08 Wrong candidate hash.
09 Null evidence path.
10 List evidence path.
11 Parent traversal evidence path.
12 Missing evidence file.
13 Null evidence digest.
14 Wrong evidence digest.
15 List evidence digest.

## Verification

Changes are committed to GitHub. These test variants have NOT been executed in this session. A GitHub-only source audit does not provide Windows build, model tool-call, disk readback, GPU correctness, soak, packaging or independent certification receipts. Do not mark any of those gates PASS.

## Follow-up

Run `python3 -m unittest discover -s tools -p 'test_verify_ide_e2e_receipts.py' -v` on a checked-out repository. Capture CI logs and fix failures. Then prioritize native model-originated editFiles disk readback and tool-result reinjection; finish remaining Windows GUI and Deep2 GPU gates before certification.
