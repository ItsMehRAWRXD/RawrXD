# Batch 18 — CI, ToolResult and receipt JSON corrections

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Three confirmed source defects corrected

1. Windows CI workflow contained a literal backslash-n in the `for /f` vswhere setup line. This could break the command that initializes MSVC.
2. ToolResult reinjection used escaped backslash-n strings in its stdout/stderr labels, producing literal `\\n` text rather than newline separators.
3. JSON certification receipts accepted duplicate fields via the default `json.loads` behavior, allowing ambiguous values such as two `status` fields.

## Commits

- `138eae30a97b6c087bc1149c916ed67b892fef67`: fix Windows MSVC workflow newline.
- `5af39cc9fce1c6b648cef8a58bbe05f62e79e0ba`: fix ToolResult newline separators.
- `82df697e0f10e4b05de5d5f3e7820380dff9e40c`: reject duplicate JSON receipt fields.
- `f840f49d19732c7fc6a5c19b11c7c2be82d88332`: regression test for duplicate PASS/FAIL status.

## Static checks

Fetched latest production parser, portable parser and workflow from GitHub and checked:
- parser fragments identical
- Windows workflow no longer contains the literal escaped newline at MSVC setup
- stdout/stderr formatting uses C++ newline escapes
- thread-local tool catalog remains present
- normal-loop catalog and empty-generation guard remain present

These are structural checks only, not executed C++ or Windows acceptance tests.

## Remaining 15 acceptance gates

1. Windows source build.
2. CTest.
3. Parser protocol regression.
4. Tool catalog routing.
5. Model-generated tool call.
6. Mutation authorization.
7. editFiles disk write.
8. Exact disk readback.
9. ToolResult reinjection.
10. Strict cancellation.
11. Crash recovery.
12. Deep2 CPU numerical correctness.
13. GPU numerical correctness.
14. Soak and packaging.
15. Independent certification.

No complete E2E certification receipt was obtained. Do not promote.
