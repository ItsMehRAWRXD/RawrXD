# Qwen4Exp Gated Residual numerical-contract slice

This is a dependency-free C++20 source-only **arithmetic reference** for a single Qwen4-Exp Gated Residual (GR) read/write operation. It is deliberately **not wired to Deep2/Vulkan** and does **not** certify any Qwen4Exp model or replace any existing certificate.

Build the portable CPU contract (no Vulkan benchmark):

```sh
g++ -std=c++20 -O2 -Wall -Wextra -Werror test_gr.cpp -o test_gr
./test_gr
```

Model-source mapping (Transformers `Qwen4ExpTextGatedResidual`): group-size `hidden` RMSNorm with gamma=`1+norm_delta`; down projection; division by `hc_count`; SiLU; up projection and sigmoid; weighted stream mean; injection=`2*sigmoid(inject_proj(normed)/hc_count)`; write=`original_stream_state + injection*block_output`.

## Production integration contract

* Map tensors from verified GGUF metadata; validate shapes and offsets before GPU admission. GGUF layouts and quantized matrix orientations must be verified against the local model, not guessed from this row-major reference.
* Do **not** call `cpu_gr_read`, `cpu_gr_write`, or `cpu_gemv` from the GPU-only production certifier. Bind the same equations to already-certified Vulkan GEMV/normalization/activation/elementwise primitives, maintain GPU-resident intermediates, and fail closed if any primitive or quantized weight is unsupported.
* Compare GPU outputs to an independently computed reference for GR read, GR write, and both operations composed. Include nonzero mixer and injection weights, multiple streams, edge-case shapes, NaN rejection, and repeated decode positions.
* Do not change `FULL_MODEL_CERTIFIED` status until architecture-specific QSA, GDN, PLE, MoE, final output and autoregressive decode all pass **full-model** independent parity; protect the previous Llama receipt.
* Benchmark execution on R9700/Vulkan remains paused pending explicit resume authorization.

Full provisional gate ledger: `QWEN4EXP_FAIL_CLOSED_INVENTORY.md`.

MSVC smoke build command from a Developer Command Prompt: `cl /nologo /std:c++20 /EHsc /W4 test_gr.cpp` (not executed in this environment).
