# Deep2 ModelPlusContext — integration source drop

This is a dependency-free C++17 planning and backend contract module, not a complete Vulkan attention implementation. It compiles and runs its capacity tests without external dependencies. It **does not** claim a working million-token context or GPU compute integration.

## Compile
`g++ -std=c++17 -Wall -Wextra -Werror context_gpu.cpp test.cpp -o context_gpu_test && ./context_gpu_test`

## Integrate with F:\\rawrxd
1. Read actual GGUF geometry; populate `Geometry` with correct per-layer KV dimensions. MLA compressed representation is a separate format. Do not use `mla_latent_dim` if your engine stores expanded K/V.
2. Determine the model's **validated** max positions; do not claim one million merely because memory fits.
3. Query actual free memory on each physical Vulkan device, reserve safety headroom, and call `plan_context`.
4. Implement `ContextBackend` callbacks using the existing native Vulkan backend on device 4. Append must upload real packed KV to device-local pages. Attention must perform real attention against the remote resident cache and return the output to device 0. `wait_context` must establish real queue completion.
5. Connect the callbacks at the attention boundary of `Executor::ExecuteToken`; do not copy full KV to device 0 each token. Do not use process-static QuantDot device selection for remote operations.
6. Make ownership per-session and per-layer; add page tables, eviction safety, RAM/NVMe tiering, INT8 scales and numerically verified quantization before enabling larger contexts.
7. For non-coherent mapped Vulkan staging allocations, flush host writes and invalidate device writes with correctly aligned ranges, after explicit fence synchronization.
8. Record single-GPU vs remote-KV logits, argmax, throughput, transfer bytes, peak memory and 4K→32K→128K→512K→1M endurance.

## Important limitations
- `ContextSession` enforces valid callback wiring and per-token position, but the application owns real KV page storage and per-layer completeness.
- INT8 estimate excludes scale metadata except for caller-provided overhead; the actual quant format may require much more.
- `TieredContext` and `SplitModel` are **planning verdicts**, not implemented paging or model splitting.
- Model's trained/validated context limit and long-range quality remain independent acceptance gates.
