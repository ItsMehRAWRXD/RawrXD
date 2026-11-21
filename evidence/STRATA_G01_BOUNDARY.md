# G01 boundary: two distinct VulkanCompute classes — 2026-11-21

Sprint gate: **identify the authoritative compiled adapter class (G01)**

## Finding

There are **two different `VulkanCompute` classes**, and they are the source of every C2039/C2039-style failure in this workstream:

| Declaration | Owns | Used by |
|---|---|---|
| `src/deep2/vulkan_compute.h:90` — `class VulkanCompute` | `gemvSuccess_`, `queueSubmitCount_`, **`queueSubmitCount_`**, `TrimUnpinnedWeightCache()`, and my `weight_cache_retention_` | deep2 engine / `Deep2::VulkanCompute backend_` |
| `include/vulkan_compute.h:88` — `class VulkanCompute` (CPU reference) | `SetQuantWeightBudgetBytes(size_t)` (inline, :207), `quant_weight_budget_bytes_` | **`quant_dot_dispatch.cpp` `Gpu()` / `GpuFor()`** |

`quant_dot_dispatch.cpp:50` holds `static VulkanCompute gpu;` resolved to the **CPU reference class** — which is why:
- `vk->SetQuantWeightBudgetBytes(...)` compiles there, and
- `vk->SetWeightCacheRetention(...)` fails with `C2039` (the method exists only on the deep2 class).

The adapter `CPUInference::VulkanCompute` (`include/vulkan_compute_cpu_ns.hpp:53`, owning `std::unique_ptr<Deep2::VulkanCompute> backend_` at :389) is a **third** type and is not what `quant_dot_dispatch.cpp` uses.

## Consequence

The retention policy cannot be plumbed through `QuantDot` until the two same-named classes are disambiguated. Any further attempt to add a method to "VulkanCompute" without naming the header will keep hitting the wrong class.

## Two viable corrections

**A. Disambiguate (preferred).** Rename the deep2 class (e.g. `Deep2::VulkanCompute` → `Deep2::QuantWeightCache`) or wrap it, then have the CPU-reference class hold a pointer to it and forward retention explicitly. This makes the ownership chain legible and is a prerequisite for G36/G39 (cache ownership and concurrent policy isolation).

**A. Minimal bridge (interim).** Add `SetWeightCacheRetention(bool)` to the **CPU reference class** in `include/vulkan_compute.h` (no `backend_` — store a bool), and have the deep2 trim consult the same policy through a shared accessor. Documented as process-scoped, not request-scoped.

## Status

```
G01=RESOLVED (two classes identified, exact headers/lines)
G02=BLOCKED on A or B decision
G11=OPEN (process-global policy remains)
POINTER_REUSE/ownership=G36 (unaffected, still open)
TREE=GREEN (bench builds)
```

## Recommendation

Take **A** (disambiguate) before adding more policy surface: it is the same work required later for concurrent request isolation (G39) and cross-model cache ownership (G36), and it prevents the recurring wrong-class edits that have consumed this workstream.