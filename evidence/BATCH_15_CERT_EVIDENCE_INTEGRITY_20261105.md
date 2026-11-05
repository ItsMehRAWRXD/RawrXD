# Batch 15 — Certification evidence integrity

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Finding

The 15-gate receipt verifier previously accepted any nonempty evidence file, including arbitrary absolute paths and paths escaping the receipt directory, and did not verify evidence-file contents against a digest. This could incorrectly elevate unrelated or modified files into a PASS receipt.

## Source and test changes

- `e2442804a0c2cc7bd4a159abc337bf6648745ffe`: require evidence files under receipt directory and validate each file's SHA-256 against `evidence_sha256`.
- `319320b07f6d606b4c8412ed027ae1484b8ca262`: update positive fixtures with hashes; test tampered hash, missing hash, traversal, absolute paths, missing and empty evidence.
- `d9432fa3071be7a65695b8ffc2b23e92f08921cf`: execute verifier unit tests in portable CI when relevant files change.

## Fifteen certification gates (all still require real runtime evidence)

01 Source build
02 CTest
03 Protocol parser
04 Tool catalog
05 Model-originated tool call
06 Mutation authorization
07 editFiles disk write
08 editFiles disk readback
09 ToolResult reinjection
10 Cancel A→Stop→B
11 Crash recovery
12 Deep2 numerical correctness
13 GPU correctness
14 Soak and package
15 Independent certification

## Verification limitations

GitHub writes are confirmed by commit SHA. No CI success, Windows runtime pass, GPU validation or independent certification was obtained in this session. SHA-256 verifies bytes against a receipt, not the authenticity of the test executor or truthfulness of the evidence. A malicious producer can forge both. The verifier is one gate in a trusted certification workflow, not proof of complete product correctness.

## Next highest-impact work

- Obtain actual GitHub Actions logs and fix test failures.
- Establish real authorized model → editFiles → disk readback → ToolResult acceptance on Windows.
- Bind receipts to a trusted signer/test executor and exact source + binary identity.
- Run native GUI T05/T10/T18/T19, Deep2 CPU/GPU correctness, package T24, independent T25.
