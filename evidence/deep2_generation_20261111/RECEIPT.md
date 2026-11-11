# Deep2 OpenAI generation receipt

```ini
SERVER_EXE=F:\\rawrxd\\build\\bin\\Release\\deep2_openai_server.exe
SERVER_PID=35856
SERVER_SHA256=EDA3E260E0E8AF336B85B030A31B521E43FC665E2FD232051732C50CA4A34205
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
ENDPOINT=http://127.0.0.1:11436
HEALTH=HTTP_200
MODELS=HTTP_200
CHAT_COMPLETIONS=HTTP_200
GENERATION=PASS
FINISH_REASON=stop
EXACT_MARKER_DEEP2_OK=FAIL_MODEL_DID_NOT_EMIT_MARKER
GPU_POLICY=CPU_HOST_DECODE_FLOOR
```

The server loaded 201 tensors and reported `MODEL_LOAD=PASS`. The completion
returned 32 tokens and `finish_reason=stop`, but the model produced a
conversational Spanish translation rather than the requested exact marker.
This proves endpoint generation, not exact-response compliance or agentic
tool-call acceptance.
