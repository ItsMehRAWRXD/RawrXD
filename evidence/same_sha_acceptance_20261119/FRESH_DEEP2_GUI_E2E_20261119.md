# Fresh Deep2 GUI E2E

## Scope

- Source checkpoint before commit: `fd3ab5d84191de822f82b19525953e017c12d3f3`
- Executable: `build_e2e_recovery_20261119/bin/Release/RawrXD-Win32IDE-Native.exe`
- Executable SHA-256: `911BBCFB1340571EC7BD389B7EF60647335D14E4F9E86BE86E18635483B17F0F`
- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Model SHA-256: `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0`
- Environment: `RAWRXD_CHAT_BACKEND=deep2`, `RAWRXD_MODEL_PATH=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`

## Observed

- GUI launched successfully.
- Model selector exposed the configured local GGUF.
- Input control `1202` accepted `What is 2+2?` and the Send action `1204` was invoked.
- The input was consumed and the Stop control became enabled, showing that the request entered the generation path.
- The transcript remained at the welcome text during the bounded observation window; no response or terminal completion was observed.
- The exact test process was stopped after it remained active without producing a response.
- No request-attributable GPU dispatch witness was captured.

## Disposition

```ini
GUI_INPUT_ROUNDTRIP=PASS
DEEP2_ROUTE_SELECTED=PASS
LOCAL_GGUF_ADMISSION=PASS
DEEP2_GUI_RESPONSE=FAIL_UNVERIFIED
GPU_DISPATCH_WITNESS=NOT_CAPTURED
GUI_CHAT_E2E=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

The source fixes in this checkpoint remove the premature native-agent admission dependency and allow `RAWRXD_MODEL_PATH` to initialize Deep2. They do not establish successful token generation; the synchronous `GenerateSync` path remains the next blocker.
