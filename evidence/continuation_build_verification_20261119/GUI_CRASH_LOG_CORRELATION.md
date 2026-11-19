# Post-submission GUI failure correlation

- Executable: `build_sprint_20261119/bin/Release/RawrXD-Win32IDE-Native.exe`
- SHA-256: `944AF94221770A0849148E62226805E1D730F0C65AEEC1519A35E8B0C9065C6B`
- Input staging: `CHIN` accepted, 33-byte prompt.
- Runtime log: `chat_runtime.log` records `CHAT_SEND_ATTEMPT`, `BACKEND_REQUEST_START`, and `CHAT_SEND_ARMED`.
- Backend route: `bigdaddyg-productivity-local:latest` through Ollama/WinHTTP, not Deep2.
- Last backend log event: `WinHttpOpenRequest ok; sending`.
- Response: no terminal response event before process exit `-1`.
- Windows Application event query: no matching RawrXD fault event found for the run window.
- GPU dispatch: not established; this request selected the Ollama route.

The input boundary is now proven separately. The remaining failure is a production Ollama-route process exit after request send, and it cannot certify Deep2 GPU GUI execution. The next fix must either capture the native fault or force an explicitly configured local Deep2 route before retrying GPU acceptance.

```ini
INPUT_STAGE=PASS
REQUEST_ARMED=PASS
OLLAMA_ROUTE=CONFIRMED
TERMINAL_RESPONSE=FAIL
PROCESS_EXIT=-1
DEEP2_GPU_ROUTE=NOT_SELECTED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
