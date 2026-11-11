# DEEP2_QWEN36_FULL_MODEL_PARITY_001

## Disposition

`FULL_MODEL_PARITY=FAIL_REPORTED` · `PROMOTE=0`

The CPU GDN intermediate/state parity gate is closed separately. This receipt
tests the complete model path against a separate Ollama/llama.cpp execution of
the same GGUF and records a deterministic token disagreement.

## Shared model provenance

```ini
MODEL=F:\\OllamaModels\\Qwen3.6-35B-A3B-GGUF\\Qwen3.6-35B-A3B-Q4_K_M.gguf
MODEL_SHA256=4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D
DEEP2_EXECUTABLE=F:\\rawrxd\\build_reap\\bin\\deep2_bench_tps.exe
DEEP2_EXECUTABLE_SHA256=FBBA1A8AE1F82764F420E2B5E8A7A1ED045EC64EA95A89D2047614AD6BE45E12
ARCH=qwen35moe
BLOCKS=40
EMBEDDING=2048
QUANTIZATION=Q4_K_M
```

The reference model was imported locally as `qwen36-reference-local:latest`
from that exact file. Ollama reported architecture `qwen35moe`, 34.7B
parameters, and a 22 GB model footprint. No cloud model was used.

## Deterministic test

The initial exploratory comparison incorrectly used token `14556`, which is
lowercase `hello`, while the reference prompt was uppercase `Hello`. That
comparison is invalid and is not used for the disposition below.

The model tokenizer maps uppercase `Hello` to token ID `9419`. The corrected
comparison used that exact ID for Deep2 and the raw text `Hello` for Ollama.
The GGUF-derived tokenizer reconstructed the Ollama completion as token IDs
`11, 271` (`,`, `ĊĊ`).

```text
deep2_bench_tps.exe --model Qwen3.6-35B-A3B-Q4_K_M.gguf \
  --tokens "9419" --decode 2 --cpu --serial-prefill --no-batch
```

Deep2 result:

```ini
DEEP2_EXIT=0
DEEP2_LOGITS_FINITE=YES
DEEP2_INPUT_TOKEN=9419
DEEP2_TOKENS=151353 96999
DEEP2_TOKEN_TEXT=ª½ / æĽ¾ (from GGUF vocabulary)
ALIGNED_DEEP2_LOGITS_CAPTURE=deep2_logits_Hello_aligned/d2_logits_pos0.bin,d2_logits_pos1.bin
ALIGNED_DEEP2_ARGMAX=151353,96999
REFERENCE_LOGITS=NOT_EXPOSED_BY_OLLAMA_API
DEEP2_VERDICT=PASS
```

The independent Ollama reference used the same model, raw prompt mode, greedy
settings, and two generated tokens:

```json
{
  "model": "qwen36-reference-local",
  "prompt": "Hello",
  "raw": true,
  "temperature": 0,
  "top_k": 1,
  "top_p": 1,
  "num_predict": 2,
  "eval_count": 2,
  "response": ",\n\n",
  "done": true,
  "done_reason": "length"
}
```

Reference receipt: `ollama_hello_run.json`.
Reference tokenization: `11 271` from `tmp_build/qwen36_tokenize_reference.py`.
Deep2 raw output: `deep2_Hello_aligned_run.txt`.

## Result

```ini
REFERENCE_BACKEND=OLLAMA_LLAMA_CPP
REFERENCE_MODEL=qwen36-reference-local:latest
REFERENCE_EXECUTION=PASS
DEEP2_EXECUTION=PASS
REFERENCE_TOKEN_IDS=11 271
TOKEN_SEQUENCE_EQUAL=NO
INPUT_ALIGNMENT=PASS_FOR_CORRECTED_RUN
FULL_MODEL_LOGITS_PARITY=NOT_AVAILABLE_FROM_REFERENCE_API
FULL_MODEL_PARITY=FAIL_REPORTED
OLLAMA_LOGPROBS_PROBE=NO_LOGITS_FIELD
LLAMA_SERVER_BINARY=INSTALLED
LLAMA_SERVER_REFERENCE_LOGITS=NOT_AVAILABLE_FROM_ACTIVE_API
```

The token disagreement is evidence that the complete Deep2 path is not yet
validated against the independent backend. It may involve attention, output
projection, tokenizer/BOS handling, or another full-model interaction. The
GDN kernel parity result must not be promoted to full-model parity.

## Follow-up gates

```ini
TOKENIZER_AND_BOS_ALIGNMENT=OPEN
FULL_LOGITS_REFERENCE_CAPTURE=OPEN
ATTENTION_PARITY=OPEN
OUTPUT_PROJECTION_PARITY=OPEN
VULKAN_GDN=FAIL_CLOSED
GPU_EXPERT_PLACEMENT=NOT_RUN
PROMOTE=0
```
