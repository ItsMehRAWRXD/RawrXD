# Fresh native GUI acceptance attempt

- Executable SHA-256: `944AF94221770A0849148E62226805E1D730F0C65AEEC1519A35E8B0C9065C6B`
- Executable: `build_sprint_20261119/bin/Release/RawrXD-Win32IDE-Native.exe`
- Harness: `evidence/AGENT_SHELL_CHANNEL_RECOVERY_001/harness_chatwindow_600s.ps1`, evaluated with the fresh executable and isolated output directory.
- Model environment: `RAWRXD_DEEP2_PROBE_MODEL=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Window: `RawrXD_IDE_Window` found.
- Controls: input/send/stop/model combo found; combo count `178`.
- Failure: `INPUT_LEN_AFTER_SET=0`, empty input, `PROMPT_SUBMITTED=1`, then `CRASH_DURING_GEN exit=-1`.
- Cancellation: not proven (`CANCEL_OK=0`).
- GPU dispatch: not attributable; no valid request reached inference.

This is a reproducible GUI-harness/product failure, not an acceptance pass. The input-control boundary and crash need a targeted diagnostic before retrying GPU-backed chat.

```ini
FRESH_GUI_LAUNCH=PASS
CONTROL_DISCOVERY=PASS
INPUT_INJECTION=FAIL
REQUEST_COMPLETION=FAIL
GPU_BACKEND_EVIDENCE=NOT_APPLICABLE
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
