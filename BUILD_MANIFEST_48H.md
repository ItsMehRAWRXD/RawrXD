# RawrXD ASM Build Manifest & Accountability Log (Last 48 Hours)
**Dump Date**: May 26, 2026
**Scope**: `D:\rawrxd\src\asm`

This document serves as the absolute "builder's plug" to index all structural `.asm` systems, modules, and components touched or generated within the last 48-hour development cycle. 

---

### Core Hardware Engine & Game Mechanics (May 26)
These are the latest pure x64 MASM implementations, heavily accelerated with AVX/SSE logic and strict memory alignments.

* `Sovereign_DAG_VM_Fixed.asm` (5/26/2026 3:36 AM)
* `Sovereign_Render_Queue_Fixed.asm` (5/26/2026 3:36 AM)
* `rag_gfx.asm` (5/26/2026 3:36 AM)
* `Sovereign_GGUF_Parser.asm` (5/26/2026 3:36 AM)

### Sovereign OS, Kernel, and Subsystem Layer (May 25-26)
The structural foundation bridging monolithic architecture, memory guards, JIT, and fault handling.

* `Sovereign_OS_DAG_Compiler.asm` (5/26/2026 3:25 AM)
* `Sovereign_JIT_Engine.asm` (5/26/2026 3:25 AM)
* `Sovereign_OS_Core.asm` (5/26/2026 2:49 AM)
* `Sovereign_Final_Linkage.asm` (5/26/2026 2:35 AM)
* `Sovereign_Runtime_Bootstrap.asm` (5/26/2026 2:35 AM)
* `Sovereign_Network_Sync.asm` (5/26/2026 2:14 AM)
* `Sovereign_Renderer_AVX512.asm` (5/26/2026 2:14 AM)
* `Sovereign_Kernel_Registry.asm` (5/26/2026 2:14 AM)
* `Sovereign_OS_MemoryGuard.asm` (5/26/2026 2:14 AM)
* `Sovereign_Runtime_Relocator.asm` (5/26/2026 2:06 AM)
* `Sovereign_PE_Emitter.asm` (5/26/2026 2:06 AM)
* `Sovereign_Stream_Ingest.asm` (5/26/2026 1:46 AM)
* `Sovereign_FaultLog.asm` (5/25/2026 11:38 PM)
* `Sovereign_Fault_Handler.asm` (5/25/2026 11:37 PM)
* `Sovereign_Manifest_Generator.asm` (5/25/2026 11:32 PM)
* `Sovereign_Stability_Baseline.asm` (5/25/2026 11:29 PM)
* `Sovereign_Execution_Graph_ABI.asm` (5/25/2026 11:21 PM)
* `Sovereign_AppendLog_SHA256NI.asm` (5/25/2026 9:44 PM)
* `Sovereign_Runtime_Run.asm` (5/25/2026 9:44 PM)
* `Sovereign_TestBench_Harness.asm` (5/25/2026 9:35 PM)
* `Sovereign_Ultra_HFT.asm` (5/25/2026 11:38 PM)
* `sovereign_media.asm` / `sovereign_macros_smoke.asm` / `sovereign_kernels.asm` / `sovereign_guard.asm` (5/25/2026 9:32 PM)
* `Sovereign_Final_Handoff.asm` / `Sovereign_Compiler_Pass.asm` / `Sovereign_Build_Gate.asm` (5/25/2026 9:32 PM)

### Commits, Compilers, and Allocators (May 25)
Integrations for the testbench, allocation systems (linear/RB-tree), and UI dispatcher wrappers.

* `WOM_Commit_SHA256NI.asm` (5/25/2026 9:28 PM)
* `win32ide_main.asm` (5/25/2026 9:22 PM)
* `wom_commit.asm` / `zerocopy_ring_bridge.asm` (5/25/2026 9:07 PM)
* `vram_pressure_monitor.asm` / `tsconfig_runtime.asm` / `security_identity.asm` (5/25/2026 8:57 PM)
* `solo_standalone_compiler.asm` / `rawr_rbtree.asm` / `rawr_linear_allocator.asm` (5/25/2026 8:57 PM)

### RawrXD Dispatchers, IPC, Mesh, & Neural Layers (May 25)

* `RawrXD_Swarm_Consensus.asm` / `RawrXD_Sovereign_MinimalEntry_v224.asm` (5/25/2026 8:57 PM)
* `RawrXD_PE64_IAT_Fabricator_v224.asm` / `RawrXD_PE_Writer.asm` (5/25/2026 8:57 PM)
* `RawrXD_Parallel_Loader.asm` / `RawrXD_NeuralMeshSync.asm` (5/25/2026 8:57 PM)
* `RawrXD_Native_Core.asm` / `RawrXD_NanoQuant_Streaming.asm` (5/25/2026 8:57 PM)
* `RawrXD_MonacoCore.asm` / `RawrXD_MeshConsensus.asm` / `RawrXD_Mesh_Stress.asm` (5/25/2026 8:57 PM)
* `RawrXD_IPC_Dispatcher.asm` / `RawrXD_Hotpatcher.asm` / `RawrXD_Emitter_v1.asm` (5/25/2026 8:57 PM)
* `RawrXD_Agent_Dispatch.asm` (5/25/2026 8:28 PM)

### Inference, Kernels & Dynamic Prompts (May 25)
* `inference_kernels.asm` / `titan_core.asm` / `titan_loader.asm` 
* `kernel_dispatch.asm` / `kernel_q5_k_simd.asm` / `tensor_alloc.asm`
* `dequant_simd.asm` / `refactor_dequant_simd_src.py`
* `RawrXD_DynamicPromptEngine.asm` / `RawrXD_DynamicPromptEngine_Templates.asm` (along with `.obj` builds)

### GPU Silicon, AMX/AVX RDNA3 Codecs (May 24)
* `RawrXD_RDNA3_Shadow_Pager.asm` / `RawrXD_Silicon_PUF_Signer.asm` 
* `RawrXD_RDNA3_Speculative_Preload.asm` / `RawrXD_RDNA3_Telemetry_Refiner.asm`
* `RawrXD_RDNA3_Silicon_Authenticator.asm` / `RawrXD_RDNA3_Sovereign_Codec.asm`
* `RawrXD_RDNA3_MMIO_Recon.asm` / `RawrXD_RDNA3_Neural_Entropy_Shield.asm`
* `RawrXD_RDNA3_Power_Sovereign.asm` / `RawrXD_RDNA3_HugePage_Expander.asm`
* `RawrXD_RDNA3_Elastic_Manifest.asm` / `RawrXD_RDNA3_Custom_Inflator.asm`
* `RawrXD_RDNA3_3X_Virtualizer.asm` / `RawrXD_RDNA3_3x_Expander.asm`
* `RawrXD_KFD_Sovereign_Interface.asm` / `RawrXD_BitPlane_Transcoder.asm`
* `avx512_matmul.asm` / `RawrXD_QuantKernels_Full.asm` / `RAWRXD_KV_APERTURE.asm`

### Monolithic Handlers & Endpoints (May 24)
* `terminal_pipe_engine.asm` / `rawrxd_scc.asm`
* `inference_core.asm` / `monolithic/main.asm` / `monolithic/lsp.asm`
* `RawrXD_Camellia256_Auth.asm` / `RawrXD_Camellia256.asm`

---
*All files verified inside `D:\rawrxd\src\asm`. This manifest is physically dropped to ensure the IDE context doesn't lose track of its architectural footprint.*