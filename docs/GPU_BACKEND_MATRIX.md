# RawrXD GPU Hardware Backend Tracking Matrix

This document tracks the implementation status, operator coverage, and technical debt for vendor-specific compute backends within the RawrXD engine.

## Hardware Tiering & Support Matrix

| Backend | Vendor Target | Integration Status | Active TODOs | Primary Execution Path |
| :--- | :--- | :--- | :--- | :--- |
| **Vulkan** | Universal (NVIDIA/AMD/Intel) | **Tier 1 (Primary)** | 0 | Custom Assembly / KV Cache Kernels |
| **OpenCL** | Legacy / Embedded GPUs | **Tier 2 (Secondary)** | 24 | ggml-opencl.cpp |
| **SYCL** | Intel OneAPI / Arc | **Tier 2 (Secondary)** | 14 | ggml-sycl.cpp |
| **CANN** | Huawei Ascend NPUs | **Tier 3 (Experimental)** | 17 | ggml-cann.cpp |

---

## Detailed Stub Breakdown

### Tier 1: Vulkan (Primary Kernel Runtime)
* **Status:** Operational / Native.
* **Architecture:** Custom MASM64 / Vulkan assembly compute pipeline with shared-memory telemetry.
* **Focus:** Direct GGUF loading, high-throughput KV cache allocation, and sub-millisecond execution.

### Tier 2: OpenCL (ggml-opencl.cpp - 24 TODOs)
* **Kernel Synchronization:** Pending fine-grained event barriers for async queue submissions.
* **FP16 GEMM Variants:** Incomplete matrix-vector multiplication kernels for FP16/INT4 quantized tensors.
* **Device Selection:** Fallback memory querying on non-standard OpenCL platforms.

### Tier 3: SYCL (ggml-sycl.cpp - 14 TODOs)
* **USM Allocation:** Unified Shared Memory allocation hooks require host-pinned memory optimization.
* **DPCPP Operators:** Missing vectorized implementations for ggml_sycl_op_flatten and complex soft-max reductions.

### Tier 3: CANN (ggml-cann.cpp - 17 TODOs)
* **Ascend ACL Bridge:** Context setup and ACL stream mapping require async callback stabilization.
* **Tensor Formatting:** Missing automatic format layout conversions (ND to 5HD) for specialized Huawei NPU hardware.

---

*Last Updated: 2026-07-29 13:13:20*
