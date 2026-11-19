# GUI input staging retry

The production source defines chat input as control ID `1202` and supports the `CHIN` (`WM_COPYDATA`, `0x4348494E`) staging path. The prior harness wrote directly to the cross-process edit and observed length zero.

- Executable SHA-256: `944AF94221770A0849148E62226805E1D730F0C65AEEC1519A35E8B0C9065C6B`
- `WM_COPYDATA` staging: accepted (`INPUT_STAGE_RESULT=1`)
- Prompt payload length: `33`
- Send: submitted
- Response: failed; process exited `-1`
- Cancellation: not proven
- GPU dispatch: not established

This isolates the original input-injection failure from the remaining production crash. The crash occurs after accepted input staging and before a valid response, so GUI runtime acceptance remains open.

```ini
INPUT_STAGE_ROUNDTRIP=PASS
REQUEST_COMPLETION=FAIL
PRODUCTION_CRASH=REPRODUCED
GPU_BACKEND_EVIDENCE=NOT_ESTABLISHED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
