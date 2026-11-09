# OUTPUT_GATE.md — FOUR_PANEL_COMPLETION_001 Track H

```
PROMOTE=0
TIP_CLIMB=HOLD
OUTPUT_PANEL=FAIL_CLOSED
SOURCE_WIRED=1
RUNTIME_REACHED=PARTIAL
HWND_OUTPUT_PANEL=NOT_RUN
CANDIDATE_EXE_SHA256=873140373C0177611709897928FFCEA7B572E11F4D690D07FEB1312EA2E90941
HARNESS_EXE=bin/output_gate.exe
HARNESS_SHA256=76DE2EEFB249796F6E4BC3C0FCEA2681EAA450E0E1D74969798B50334180B017
```

## Source changes
- Seed channels: Build, Tasks, ExtensionHost, Ollama, Deep2, Diagnostics (plus Output/Errors/Debug/Find)
- `postOutputPanelSafe(text, tabName)` channel payload (`channel\0text`)
- `WM_IDE_OUTPUT_APPEND_SAFE` handler parses channel (Win32IDE_Core.cpp)
- BuildRunner posts to **Build** channel via safe post
- Timestamps for Build/Diagnostics tabs

## Harness results (logic isolation)
| Assertion | Result |
|-----------|--------|
| no cross-channel corruption under threads | PASS (harness) |
| Build/Deep2 buffers | PASS (harness) |
| channel switch keeps buffers | PASS (harness) |
| real build → Build channel HWND | NOT_RUN |
| inference → Deep2/Ollama HWND | NOT_RUN |
| ExtensionHost activation channel | NOT_RUN |
| search/copy/clear/scroll HWND | NOT_RUN |

## Remaining FAIL_CLOSED
HWND product E2E on relinked candidate: real build + inference + ExtensionHost → correct channels without corruption/duplication.
