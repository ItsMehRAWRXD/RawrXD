# Fresh GUI Deep2 route acceptance

- Source revision before this change: `272df5121cce3e9f17d6195d88d801a9432d0ae7`
- Change: `RAWRXD_MODEL_PATH` valid GGUF is seeded and preferred by the production selector during initial and asynchronous catalog publication.
- Model: `F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Executable SHA-256: `4FA8FD75BA9E50178449C7D635EB1185B1EC710BE37CD2879907282484204BFC`
- Environment: `RAWRXD_CHAT_BACKEND=deep2`, `RAWRXD_MODEL_PATH` set to the model above.
- GUI launch/control discovery: PASS.
- CHIN input staging: PASS, 33-byte prompt.
- Runtime model route: `BACKEND_REQUEST_START ... model=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`.
- Backend terminal event: PASS, `BACKEND_REQUEST_END request_id=1 success=0 stop=0`.
- UI terminal event: PASS, `ui_update request_id=1 rendered=1 complete=1 response_bytes=90`.
- Transcript completion: PASS, `RESPONSE_END request_id=1 ... bytes=90`.
- GPU counters: not emitted by this GUI receipt; GPU dispatch count remains unverified.

The previous Ollama-route exit was not reproduced after explicit local-route selection. The response was reported by the embedded Deep2 route, but this run did not establish GPU dispatch telemetry or successful-response semantics because the bridge classified the 90-byte result as unsuccessful.

```ini
LOCAL_GGUF_SELECTION=PASS
DEEP2_ROUTE_REACHED=PASS
GUI_TERMINAL_EVENT=PASS
GUI_RESPONSE_BYTES=90
GUI_SUCCESS_FLAG=0
GPU_DISPATCH=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
