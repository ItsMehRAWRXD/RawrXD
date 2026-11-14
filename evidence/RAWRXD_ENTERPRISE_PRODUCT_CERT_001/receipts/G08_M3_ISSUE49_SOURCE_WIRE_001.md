# G08 / G05 — Issue#49 useCliAgent SOURCE_WIRE (≠ PASS)

| Field | Value |
|-------|-------|
| GATE_ID | G08-01 / G05-06 (RELATED) |
| GIT_SHA | (pending commit on work/v0-first-divergence) |
| EXE_SHA256 | NOT_BUILT_THIS_RECEIPT |
| RESULT | EVIDENCE_PARTIAL |
| CROSS_SHA_CREDIT | 0 |
| REVIEWER | SELF_MEASURE |
| TIMESTAMP | 2026-11-13T22:30-05:00 |

## SOURCE_WIRED
- `Win32IDE_Issue49CliWire.cpp` + CMakeLists entry
- `AgenticLoopBridge`: FORCE_TOOL → `rawr agent` argv
- `AgentPanel` / `AgentCommands`: env → `launchCliAgentIssue49Task`
- BoundedAgent MODEL_RESIDENT via BackendOrchestrator LoadModel

## Still open for PASS
MODEL_SELECTED_TOOL remasure; tip EXE rebuild; GATE_MATRIX stays NOT_RUN.
