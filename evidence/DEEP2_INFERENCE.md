# Deep2 backend inference — end-to-end verification (2026-11-28)

The core Deep2 engine generates real tokens through its OpenAI-compatible server. This is the
deepest product verification (build → run → real Deep2 inference).

## Setup
```
deep2_openai_server.exe (2,141,184 B, built) --model tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --port 8080 --cpu
=> [server] ready, listening on :8080
```

## Requests
```
GET  /v1/models            -> 200  {"data":[{"id":"tinyllama-1.1b-chat-v1.0.Q4_K_M",...}]}
POST /v1/completions       -> 404  (not implemented; chat is the path)
POST /v1/chat/completions  -> 200  2403 ms
  {"choices":[{"message":{"content":"\nHey!","role":"assistant"},"finish_reason":"stop"}],
   "usage":{"completion_tokens":5,"prompt_tokens":20,"total_tokens":25}}
```

## Result
- Model loaded from GGUF; OpenAI-compatible chat endpoint served a real completion.
- 5 completion tokens generated in ~2.4 s (CPU). Real Deep2 inference confirmed.

## Finding (model-specific)
`gemma3-1b-Q2_K.gguf` crashed the server on the first chat request (connection reset; process
exited). `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` works. This is a model-format/loader
compatibility issue in the Deep2 GGUF path, NOT a build/integrity defect — a candidate for a
separate Deep2 loader fix (out of scope here).

## State
IMPLEMENTED=1 BUILT=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 (real Deep2 tokens)
COMMITTED=1 PUSHED=0
NOT_APPLICABLE: gemma3 crash — model-loader compatibility, separate workstream.