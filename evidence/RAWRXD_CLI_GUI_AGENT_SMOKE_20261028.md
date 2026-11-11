# RawrXD CLI/GUI agent bridge smoke receipt

Date: 2026-10-28
Source root: `F:\rawrxd`
Branch: `fix/deep2-multimodel-safety-20261025`
Source revision at test: `d35da627810f3d5a95db3eb4e04ee43b1bfe8c2a`

## Certified CLI path

| Item | Result |
|---|---|
| CLI | `F:\rawrxd\build_ide\bin-msvc\rawr.exe` |
| CLI SHA-256 | `E7222A31207F8262DAA1036934AB049F7AD99EFA10B4BFBA9057C829CAF9EBD3` |
| Backend | Ollama |
| Model | `qwen3:8b` |
| Workspace | `F:\rawrxd` |
| Mode | read-only / ask |
| Tool | `readFile` |
| Fixture | `tmp_build\cli_smoke_20261028\fixture\calc.cpp` |
| Mutation | none |
| Exit | 0 |
| ESP JSONL | `F:\rawrxd\.rawrxd\ledger\agent_esp.jsonl` |
| ESP outcome | `tool_calls=1`, `readFile PASS`, `failures=0`, `finished=PASS` |

The fixture content was returned through the real Ollama model/tool path. No
synthetic tool result was inserted.

## Certified GUI handoff

| Item | Result |
|---|---|
| GUI | `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe` |
| GUI SHA-256 | `672E1FE9CA68FEAD0CB943CFF2761FC944B67DDD26111EEF29DE2D55A54E7EE4` |
| Physical route | Chat audit/read-only request -> canonical CLI -> chat + Output |
| Visible progress | SNAP startup, CLI launch, model load, inference start |
| Visible tool events | `tool_calls_received`, `tool_start readFile`, `tool_result readFile PASS` |
| Visible final result | `RAWRXD_GUI_FINAL_PASS` and `Task completed successfully` |
| GUI process state | Returned idle after child exit |

The GUI launches the canonical CLI for Ollama audit-style requests. It does
not grant mutation approval implicitly. Set `RAWRXD_GUI_APPROVE_MUTATIONS=YES`
only when an operator explicitly wants the GUI agent to edit/build files.

## Capability failure handling

If a selected model reports that it “does not support tools”, the GUI bridge
now reports the task as a capability failure instead of presenting a zero-exit
ordinary chat completion as a successful agent task. Use a tool-capable local
model such as `qwen3:8b` for read/edit/build workflows.

## Scope boundary

This receipt certifies the Ollama CLI agent and its GUI handoff. It does not
certify native Deep2 inference, REAP, LSP, debugger, or arbitrary-model tool
support.
