# Deep2 post-endurance value gates — no dependencies

Side-only source drop for the two remaining technical proofs that materially change the project-risk profile after continuity/endurance and positional CLI are sealed.

## 1. Generation quality / clean model matrix

`src/d2_gen_quality.cpp` is a dependency-free analyzer for model stdout plus an optional decode trace. It fails closed on repetition collapse and malformed/non-finite trace values.

Recommended engine trace fields, one token per line:

```
token_ordinal=<n> token_id=<id> selected_logit=<f> selected_prob=<f> finite=1 sampler_valid=1 tokenizer_roundtrip=1 chat_template_valid=1
```

The analyzer intentionally does not declare semantic quality from a single magic score. It emits mechanical predicates and a conservative `OUTPUT_COHERENT` heuristic. Preserve the raw stdout for human/model-family review.

Run `scripts/run_model_matrix.ps1` after wiring the trace seam. It exercises the positional CLI, records hashes/outputs, runs the analyzer, and writes a TSV matrix.

## 2. 70B+ constrained-memory external proof

`scripts/run_70b_proof.ps1` runs a fixed prompt corpus against RawrXD and, optionally, a user-supplied competitor command. It records exact model SHA-256, prompt corpus SHA-256, wall time, generated-token count, median TPS, process peak working set, exit codes, and raw outputs.

The comparator is intentionally process-level: no llama.cpp/Ollama code is linked or vendored. For an apples-to-apples claim, point both engines at the same GGUF when the competitor supports it.

## Integration rule

Do not place this code in the sealed endurance certification binary. Wire the optional `D2GenQualityProbe` seam into a post-endurance diagnostic build or emit the documented trace fields from the existing decode loop.

## Build

Pure C++17:

```
cl /std:c++17 /O2 /EHsc /Iinclude src\d2_gen_quality.cpp /Fe:d2_gen_quality.exe
```

or

```
g++ -std=c++17 -O2 -Iinclude src/d2_gen_quality.cpp -o d2_gen_quality
```
