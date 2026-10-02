# RAWRXD_HTTP_AUTHORITY_CHAIN_001

First execution of the Deep2 OpenAI-compatible server against a real model.
The transport chain works. The **content** does not, and it is reported as
success.

```ini
BINARY          = build_dump_census\bin\rawr-server.exe
MODEL           = G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
BUILD_GIT_SHA   = 4cfd4ab82a9b   SOURCE_DIRTY = 1   CONFIG = Release
BIND            = loopback (127.0.0.1:11435)
```

## What passed

```text
GET  /health              200  {"status":"ok","model_loaded":true,"model_id":"tinyllama-1.1b-chat-v1.0.Q4_K_M"}
GET  /v1/models           200  {"object":"list","data":[{"id":"tinyllama-1.1b-chat-v1.0.Q4_K_M",...}]}
POST /v1/chat/completions 200  usage: prompt_tokens=18 completion_tokens=16 total_tokens=34
```

Real weights, real forward pass. `model_loaded: true` is not asserted -- the
engine reports 201 tensors, arch=llama, quant=Q4_K(type 12), and the QuantKernel
Registry registered 14 GEMV + 14 dequant kernels after reporting
`AVX512F=1 AVX512BW=1 AVX512DQ=1 AVX512VNNI=1 AVX2=1 FMA=1 F16C=1`. That CPU
feature line is independently corroborated by the execution certificate.

Request independence is enforced in code before every completion:
`engine->reset()` with a stderr checkpoint pair (`REQUEST_BEGIN` / `POST_RESET`)
asserting `kv_len` determinism, to prevent the KV-position mismatch that made
prior requests return zero tokens.

## What failed: corrupt content reported as success

Request: `{"messages":[{"role":"user","content":"The capital of France is"}],"max_tokens":16,"stream":false,"temperature":0}`

Response:

```json
{"choices":[{"finish_reason":"stop","index":0,
  "message":{"content":" Yes, the French is a|assistant|system|enjokeeps","role":"assistant"}}],
 "usage":{"completion_tokens":16,"prompt_tokens":18,"total_tokens":34}}
```

Expected: `Paris`. Delivered: role-marker text and fragments
(`|assistant|`, `system|`, `en`, `joke`, `eps`) spliced into the answer.

```text
HTTP_STATUS            = 200
FINISH_REASON          = stop
TOKENS_GENERATED       = 16
TOKENS_SERIALIZED      = 16
SIMULATED_RESPONSE     = 0
CONTENT_CORRECT        = 0     <- the check that was missing
```

This is the specific failure the proposed certificate was meant to catch. Every
field in the original spec is satisfied and the response is still wrong, because
**no field in that spec inspects the text.** Transport identity
(`TOKENS_GENERATED == TOKENS_SERIALIZED == TOKENS_RECEIVED`) proves the bytes
moved, not that they mean anything. A gate over byte counts cannot detect a
wrong answer, only a truncated or duplicated one.

## Root cause: narrowed, not confirmed

```text
CONFIRMED   template detection is faithful to the file. The server logs
            "[OpenAI] ChatTemplate=phi3"; an independent GGUF read confirms
            tokenizer.chat_template genuinely contains <|user|>, <|system|>,
            <|assistant|> and none of [INST] / <<SYS>> / <|im_start|> / <|end|>.
            Detection is not the fault.
CONFIRMED   the marker text reaches the tokenizer, and marker-like text comes
            back out of the detokenizer.
CONFIRMED   direct Deep2 inference with a RAW prompt produces correct text
            (ladder G3/G4: " the city of Paris, which is the"). The corruption
            appears only once the chat template is applied.
HYPOTHESIS  TinyLlama is a SentencePiece Llama-2-style model with a 32000-token
            vocabulary. <|user|>/<|system|>/<|assistant|> are Llama-3/Phi-3 style
            markers and are probably NOT single entries in that vocabulary, so
            each marker is split into ordinary pieces; the model's own template
            is mismatched with its tokenizer, and generated specials are
            rendered as visible text on the way back.
NOT PROVEN  the vocabulary lookup. The GGUF tensor-info walk used to read
            tokenizer.ggml.tokens desynchronised and raised MemoryError. That
            instrument failed, so the hypothesis is NOT reported as a finding.
```

Discriminating test, once a reliable vocab reader exists: look up `<|user|>`,
`<|system|>`, `<|assistant|>` in the 32000-token vocab. Absent -> hypothesis
confirmed. Present -> the defect is in detokenizer special-token handling, which
is a different fix in a different file.

## Certificate changes this forces

Add to any future HTTP authority gate:

```ini
CONTENT_NONEMPTY            = 1
CONTENT_HAS_NO_CONTROL_TOKENS = 1     <- catches |assistant| / system| leaking
PROMPT_REPLY_SEMANTIC_MATCH = 1       <- needs a reference, not a byte count
```

`SIMULATED_RESPONSE=0` is necessary and nowhere near sufficient.

## Negative controls — RUN, 2 of 6 FAIL

Executed against `rawr-server.exe` on 127.0.0.1:11437, TinyLlama loaded.
These were `NOT_RUN` when this document was first written; they are now
measured, and two of them fail.

```text
CONTROL                      STATUS   EXPECTED   VERDICT
baseline /v1/models          200      200        PASS
unknown endpoint             404      404        PASS
path traversal /../etc/passwd 404     404        PASS
malformed JSON               400      400        PASS
empty body                   400      400        PASS
missing messages             200      400        FAIL
unknown model id             200      404/400    FAIL
```

### FAIL 1 — a request with no messages returns 200

```json
{"model":"x","max_tokens":4}
->
200 {"choices":[{"finish_reason":"length","message":{"content":"\n",...}}],
     "usage":{"completion_tokens":0,"prompt_tokens":7,"total_tokens":7}}
```

A zero-token completion reported as a successful generation. Cause, in source:
`parseChatCompletionRequest` (deep2_openai_server.cpp:272) reads `messages` only
`if (j.contains("messages") && j["messages"].is_array())` and never requires it.
An absent or empty message list therefore produces an empty prompt, a real
forward pass over BOS alone, and a `200`. The status contract already declares
`InvalidInput -> 400`; nothing ever produces `InvalidInput` for this shape.

### FAIL 2 — an unknown model id is silently served

```json
{"model":"definitely-not-a-real-model","messages":[...],"max_tokens":4}
->
200 ... "model":"tinyllama-1.1b-chat-v1.0.Q4_K_M" ... "content":" Can you provide me"
```

Cause, in source: `req.model` is parsed at deep2_openai_server.cpp:258 and then
never compared against the loaded model id anywhere in the handler. The request
names one model and is served by another. The response `model` field reports the
model that actually ran, so the body is not lying — but the request was never
refused, and a client that requested model A has no error telling it so.

These two are recorded as FAIL, not as caveats. They are independent of the
content-correctness failure and were not caused by it.

## Streaming caveat found in source

On the streaming path the HTTP 200 headers are sent **before** generation
begins, so a generation failure can only be signalled as `finish_reason: "error"`
mid-stream. That is a protocol limitation rather than a bug, but a client that
only checks the status line will see 200 for a failed completion. Any client
must read the finish chunk.

## Status

```text
HTTP_TRANSPORT_CHAIN   = PASS   (health, models, completions; real weights)
CONTENT_CORRECTNESS    = FAIL   (measured, content corrupted, reported as stop)
ROOT_CAUSE             = CONFIRMED  (see RAWRXD_HTTP_TEMPLATE_ROOT_CAUSE_002.md)
NEGATIVE_CONTROLS      = RUN_4_PASS_2_FAIL
VALIDATION_HOLDOFFS    = 2        (missing messages, unknown model id)
VERDICT                = FAIL_CONTENT_CORRECTNESS
```

`VERDICT=FAIL` on this gate. The server is not a trustworthy authority for
content and must not be presented as one until the leak is fixed and re-measured.
It remains a working transport.