# RawrXD T026-T040 Batch 001

Date: 2026-11-04
Workspace: `F:\\rawrxd`
Target: `RawrXD-CLI-V2`
Binary: `F:\\rawrxd\\build_repair_candidate\\bin-msvc\\rawr.exe`
Binary size: 5,020,160 bytes
Binary SHA-256 after the cancellation, shutdown, and direct-tool repair: `CCDBBBD061E5CEC328B08DF03B27F2D0593713EB3DA87FED4AC973775583925D`
Source HEAD observed: `4e9447beecaf85963859c487d29e86473560ceca` (worktree dirty)

## Results

| Gate | Result | Physical evidence |
|---|---|---|
| T026 authoritative CLI target/source provenance | PASS for target/build identity; source cleanliness remains open | `RawrXD-CLI-V2` rebuilt from `src/rawrxd_cli_v2.cpp` with MSVC/Ninja; executable size/hash recorded above. |
| T027 `--mode` parsing | PASS | `--mode=ask` and `--mode ask` both execute; unknown mode exits 2; duplicate mode exits 2. |
| T028 mode authorization | PASS | `editFiles` in `ask` mode exits 3 with a denial; approved `autonomous` mutation exits 0. |
| T029 JSON/argument parsing | PASS for exercised contract | `--json`, `--json=true`, Unicode/space-containing values, workspace passthrough, and valid JSON stdout were exercised; duplicate `--json` exits 2. |
| T030 exact `editFiles` replacement | PASS | Unique replacement changed the fixture; missing and duplicate matches both exit 1 with `match must occur exactly once`; failed cases left content unchanged. |
| T031 Write/StrReplace persistence and policy | PASS for exercised paths | `Write` and `StrReplace` both changed the fixture under approved `code` mode; UTF-8 text and CRLF bytes were verified on disk. |
| T032 tool registry/schemas | PASS for registry/required-argument descriptors | `tools list` and `tools describe` returned canonical tools, aliases, risk, and required arguments. Unknown descriptor exits 1. Typed schema constraints remain outside this batch receipt. |
| T033 direct execution receipts | PASS for durable receipt contract | Every post-repair direct-tool attempt appended JSONL to `.rawrxd/ledger/tool_receipts.jsonl` with request ID, PID, executable path/hash, tool, args, mode, result, exit code, output/error, MOTD hash, and duration. |
| T034 workspace/path boundaries | PASS for exercised traversal | `readFile path=..\\AGENTS.md` exits 1 with `path outside workspace`; workspace-rooted reads and writes remained inside `F:\\rawrxd`. Reparse-point and shell escape tests remain open. |
| T035 direct CLI dispatch | PASS | Current executable dispatched `readFile`, `editFiles`, `Write`, and `StrReplace` through the registry and verified disk effects. |
| T036 known-good inference baseline | PASS | Current CLI with Ollama `qwen3:8b` returned `BASELINE_QWEN_OK`, exit 0, bounded to 32 requested tokens. The productivity model separately reported no tool support. |
| T037 repeated-token degeneration | PASS for bounded probe | Current CLI returned the requested distinct sequence `1 2 3 4 5 6 7 8 9 10`; no repeated-token collapse observed in that probe. |
| T038 tool-aware chat template | PASS for exercised model/path | `qwen3:8b` agent path accepted a tool-directed prompt and produced a real tool call; the non-tool-capable productivity model was rejected rather than silently treated as tool-capable. |
| T039 parse model-generated tool calls | PASS | Agent ledger recorded one model-generated `readFile` call with `ok=true` and the actual AGENTS.md contents. |
| T040 connect tool calls to registry | PASS | The same run recorded `tool=readFile`, successful dispatch, and a completed model turn with `tool_calls=1`; no synthetic tool result was used. |

## Receipts

Representative current direct-tool JSON receipt:

```json
{"tool":"editFiles","mode":"autonomous","ok":true,"exit_code":0,"output":"edited","binary_sha256":"ccdbbbd061e5cec328b08df03b27f2d0593713eb3da87fed4ac973775583925d"}
```

The full receipts are in `F:\\rawrxd\\.rawrxd\\ledger\\tool_receipts.jsonl`; the fixture files and byte/hash checks are under this evidence directory.

## Open items carried forward

- Worktree is dirty because existing build/evidence changes are present; no clean source-to-binary seal was claimed.
- T034 reparse-point/shell-escape boundaries need a separate controlled test.
- T032 typed schema/constraint certification is not claimed.
- Deep2 backend and autonomous-agent paths remain independent gates; this batch used the real Ollama path for bounded inference and tool dispatch.
- No production promotion or certification was performed.

## Post-repair receipts

The same CLI candidate was rebuilt with the Deep2 active-request cancellation fix and exercised again:

| Test | Result | Physical evidence |
|---|---|---|
| Normal one-shot Ollama run | PASS | `qwen3:8b`, `CLI_NORMAL_OK`, exit `0`, process exited normally |
| Cancelled one-shot Ollama run | PASS | `--cancel-after-ms 250`, exit `130`, `[agent] CANCELLED: user_interrupt`, process exited in `2,409 ms` |
| Shutdown cleanup | PASS | Trace reached `BackendRouter::Shutdown:done`; no timeout kill was required |
| Direct approved edit | PASS | Before SHA `359D7535...BC2F`, after SHA `DC1447F6...A7F8`, JSON receipt `ok=true` |

The CLI binary hash recorded above is the hash for these post-repair receipts. These results do not certify the separately built Win32 IDE executable.
