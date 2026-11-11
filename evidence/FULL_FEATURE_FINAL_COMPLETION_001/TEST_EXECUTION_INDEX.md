# TEST_EXECUTION_INDEX — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:08:00Z
FINAL_CANDIDATE_SHA256=EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE
PROMOTE=0
CERTIFIED=0

| ID | Track | On EA5D (final candidate) | Other SHA evidence (no inherit) |
|----|-------|---------------------------|----------------------------------|
| A | T10 | PASS (freeze 9C910599) | — |
| B | ExtensionHost | **PASS** | receipt EXT_SMOKE_RECEIPT / verify004_ext |
| C | Chat AIM | **PASS** 7/7 | CHAT_CTRL_ENTER_RECEIPT |
| D | Terminal ConPTY | **NOT_RUN** / FAIL_CLOSED on EA5D | PASS on D28128AE (`conpty_manager_receipt`) |
| E | Output | NOT_RUN GUI | PARTIAL_PASS channels on D28128AE |
| F | Problems | NOT_RUN GUI | PARSE PASS on D28128AE |
| G | Debug | NOT_RUN on EA5D | SESSION_REAL=1 on 7F8EB407 |
| H | Four-panel | NOT_VERIFIED | PARTIAL; GUI_COMBINED_E2E=NOT_RUN |
| I | Build pipeline | PASS offline (peer) | IDE HWND NOT_RUN |
| J | Deep2/Vulkan | PARTIAL | CPU+R9700; RX7800XT gap |
| K | Stability | PARTIAL | T08 sealed |
| L | Packaging | PARTIAL on EA5D | RC PASS stage BD529691 |
| M | Finish-25 current | **3/25** | T10+T16+T20 on EA5D only |
| N | Final integration | FAIL conjunction | this gate |
| O | Cert | CERTIFIED=0 | — |
