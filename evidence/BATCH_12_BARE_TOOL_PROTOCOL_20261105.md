# Batch 12 — Bare tool-call framing

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Finding
The model-reply parser recognized registered bare tool calls from the first line even when the response contained trailing text or additional lines. The parser also accepted a first-line object followed by extra text because it only searched for any closing brace. Malformed bare calls to known tools could be classified as final answers.

## Source commits
- `01c93b14689de58bef34b59a63f446c3b7d871f2`: reject trailing text and multiline bare calls in production.
- `731618716b2f021d2733dd7507cc40f2262467fb`: mirror portable parser.
- `606ad2cbc4053481ec196bfba0d1f3970cc6bede`: return protocol error for malformed bare calls to registered tools.
- `f4337b4eaf693f267797c113bbfceafdbb07db72`: mirror portable parser.
- `7d446def3cb60dcc575e327edf5b11988ef4eb21`: add 15 bare-call boundary tests.
- `4d2c2259d431cd1374c1b15e3893c4e2c13f1c96`: correctly allow trailing whitespace in cases 10/11.
- `e236438d2b1e07217eabd64c0049ba97c82a891a` and `87cf6df4e5f9e7c20f5aa73a1e3db515ec1562a8`: fix newline character literal in both parser copies.

## Fifteen test cases
1. Bare call with trailing word — reject.
2. Bare call followed by prose on second line — reject.
3. Bare call followed by second call — reject.
4. Bare call followed by extra object — reject.
5. Bare call followed by malformed tag — reject.
6. Bare call followed by prose — reject.
7. Bare call followed by DONE — reject.
8. Bare call followed by role-control token — reject.
9. Bare call followed by extra whitespace and prose — reject.
10. Bare call with trailing blank lines — accept.
11. Bare call with trailing spaces/newline — accept.
12. Bare call followed by comment — reject.
13. Bare call followed by bracketed completion marker — reject.
14. Normal bare file.read call — accept.
15. Normal bare audit.coverage call — accept.

## Important remaining limitations
- This is object-*framing* validation, not a full JSON grammar parser. A malformed object with matching outer braces may still pass.
- Production and portable parsers remain duplicated; exact-parity CI check mitigates but does not eliminate drift.
- The tests were committed but not run in this session. GitHub commit status and workflow-run queries returned empty arrays.
- No model-originated editFiles mutation receipt, native Windows IDE test, GPU numerical certification, packaging verification, or T25 certification receipt was obtained.

## Next priority
Run portable CI and inspect failures, extract one shared parser, validate JSON with a real parser, then verify authorized model-to-editFiles-to-disk-readback-to-model-result end-to-end behavior.
