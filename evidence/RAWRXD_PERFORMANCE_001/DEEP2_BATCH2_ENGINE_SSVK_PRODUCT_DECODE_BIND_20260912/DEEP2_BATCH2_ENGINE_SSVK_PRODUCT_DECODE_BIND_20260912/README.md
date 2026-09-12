# DEEP2_BATCH2_ENGINE_SSVK_PRODUCT_DECODE_BIND_20260912

Purpose: bind the already-passing packed Q2_K dual-GPU SsVk operator into the
real `Deep2::Deep2Engine` decode hot path.

This package is source-ready only. It intentionally cannot claim a live PASS.

## Contents

- `Deep2SsVkProductBind.hpp/.cpp`
  - in-process packed-Q2_K callback ABI;
  - exact 84-byte/256-weight geometry guard;
  - per-operator and per-token fail-closed authority accumulator.
- `Deep2Engine_BATCH2_BIND.patch`
  - minimal integration patch against
    `cert/gpu-forward-child-ladder-20260909`.
- `ADAPTER_TEMPLATE.cpp`
  - one intentionally failing adapter body to replace with the existing
    packed-dual product executor.
- `LIVE_GATE.md`
  - 16-token live certification contract.
- `VERIFY_BATCH2.ps1`
  - fail-closed log verifier.
- `selftest.cpp`
  - portable synthetic ABI/law test only.
- `LAW.txt`

## Critical source facts used

The cert branch already exposes `forwardTokenAllLayers`, GPU-forward counters,
Vulkan strict fallback control, and `tryVulkanGEMV` from `Deep2Engine`.

The current `generate()` decode path for N>0 already performs a full token
forward, final norm, KV advance, logits and sampling. This drop preserves that
semantic order.

`LinearW()` currently tries Vulkan before CPU and `LinearW_Range()` derives
quantized row bytes from the quant registry. The product bridge is inserted
before generic Vulkan dispatch specifically for Q2_K.

## Build self-test

MSVC:

```bat
build_selftest.bat
```

or:

```sh
c++ -std=c++17 -O2 selftest.cpp Deep2SsVkProductBind.cpp -o selftest
```

Synthetic PASS does not mint product/BW/TPS/PROMOTE authority.

## Product bind

1. Copy `Deep2SsVkProductBind.hpp/.cpp` under `src/deep2/`.
2. Add the `.cpp` to the same Deep2 target that builds `Deep2Engine.cpp`.
3. Apply the patch manually or by exact anchor review.
4. Replace `ADAPTER_TEMPLATE.cpp`'s `-999` body with the **in-process** entry
   from the existing `DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001` source.
5. Bind the callback during engine/session setup.
6. Run 16+ N>0 decode tokens with strict GPU/product flags.
7. Verify the receipt with `VERIFY_BATCH2.ps1`.

Do not spawn the evidence executable or parse its old receipt.
