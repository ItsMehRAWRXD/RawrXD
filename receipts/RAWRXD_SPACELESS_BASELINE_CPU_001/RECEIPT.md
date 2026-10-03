=== RAWRXD_SPACELESS_BASELINE_CPU_001 ===

MODEL_PATH=G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf
MODEL_SHA256=EE1CA8B716933587127F6FEB9FF5A247F1E4460E72DCF6293331B9617F8A8AA2
MODEL_ARCH=llama
MODEL_BYTES=1364397056
PROMPT=The capital of France is
PROMPT_TOKEN_IDS=5
GENERATED_TOKEN_IDS=8
GENERATED_TEXT=azureazureazurePastPastPastPastPast
TOKEN_COUNT=8
PREFILL_MS=14128.7
DECODE_MS=27010.7
DECODE_TPS=0.194
WALL_MS=41139.4
LOGITS_FINITE=1
FORWARD_PASS_OK=1
BACKEND=CPU
SPACELESS_ENABLED=0
BINARY_SHA256=C2C4B6B739940E0D2FA2AEB3401A2C52FCD5F46D790301259D1AB513CB7EBFE8
BINARY_PATH=F:\~dev\rawrxd copy\build\bin\Release\rawr.exe
RUN_TIMESTAMP=2026-10-03T02:19:00Z
VERDICT=PASS

---

MEASUREMENT NOTES:
- Run via: rawr.exe run --tokens 8 <model> <prompt>
- All layers executed CPU_FALLBACK (vulkan=0/0)
- AVX-512 detected and kernels registered
- Model load: 529 ms
- Decode completed: 8 tokens in 27.0s decode + 14.1s prefill
- Output may be repetitive due to sampling temperature=0 / greedy decode
- Full stdout/stderr captured in baseline_run2.txt

---

EVIDENCE DISCIPLINE:
This receipt is MEASURED from a runtime execution.
No claims are made about output quality.
The purpose is a reproducible pre-change baseline for SpaceLess work.

RECEIPT_STATUS=BASELINE_RECORDED
NEXT_STEP=Implement TensorIdentity struct
