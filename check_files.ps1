$files = @(
  'tests/b005_canonical_model_certification.cpp','src/canonical/gguf_adapter.cpp','src/canonical/unified_model_loader.cpp',
  'tests/b006_kv_cache_verification.cpp','src/core/memory_stubs.cpp','src/core/link_stubs.cpp','src/logging/Logger.cpp',
  'src/core/swarm_scheduler.cpp','src/core/inference_witness.cpp','src/core/gguf_swarm_plan_builder.cpp',
  'tests/b007_performance_baseline.cpp','src/runtime/TensorExecutionRouter.cpp','src/runtime/memory/PredictiveMemoryManager.cpp',
  'src/runtime/memory/TransferScheduler.cpp','src/runtime/memory/ResidencyTracker.cpp','src/runtime/memory/WorkingSetPredictor.cpp',
  'src/runtime/memory/CapacityManager.cpp','src/runtime/memory/TensorPlacementManager.cpp',
  'tests/b008_ci_integration.cpp','tests/b010/b010_weight_residency_profile.cpp','tests/b011_weight_residency_optimization.cpp',
  'certification/CertificationHarness.cpp','src/tokenizer/gguf_embedded_tokenizer.cpp',
  'src/deep2/Deep2Engine.cpp','src/deep2/K2GlobalTensorIndex.cpp','src/deep2/GGUFLoader.cpp','src/deep2/ThreadPool.cpp',
  'src/deep2/KVCache.cpp','src/deep2/QuantKernelRegistry.cpp','src/deep2/MoERouter.cpp','src/deep2/MoEWeightProxy.cpp',
  'src/deep2/MoEEliminate.cpp','src/deep2/MoEWeightsLoader.cpp','src/deep2/TensorHop.cpp','src/deep2/MoEArchitectureParser.cpp',
  'src/deep2/Deep2ExecutionGraph.cpp','src/deep2/ReverseHotpatchEngine.cpp','src/deep2/ReverseIntegration.cpp',
  'src/deep2/DualGPUHook.cpp','src/deep2/ReverseTensorRecovery.cpp','src/deep2/StreamEngine.cpp','src/deep2/StreamRouter.cpp',
  'src/deep2/FusedInferenceKernel.cpp','src/deep2/MedusaDecoder.cpp','src/deep2/WarmupScheduler.cpp','src/deep2/NUFusedPacker.cpp',
  'src/deep2/CompressedKVCache.cpp','src/deep2/NVMeStream.cpp','src/deep2/SlidingWindowEngine.cpp',
  'src/deep2/HotPatcher.cpp','src/deep2/HotPatcherSafety.cpp','src/deep2/AntiPatcher.cpp','src/deep2/TrailBrake.cpp',
  'src/deep2/PatchCache.cpp','src/deep2/BottleTTL.cpp','src/deep2/GoalSystem.cpp','src/deep2/CPUFrequency.cpp',
  'src/deep2/mars/VRAMManager.cpp','src/deep2/mars/TensorHotpatch.cpp','src/deep2/mars/DualGPUBackend.cpp','src/deep2/mars/MARSController.cpp',
  'src/reverse/ReverseEngine.cpp','src/reverse/ReverseModelLoader.cpp',
  'src/deep2/sovereign_deep2_kernels.asm','src/deep2/sovereign_q4k_gemv.asm','src/deep2/sovereign_q4k_gemv_v2.asm',
  'src/deep2/sovereign_q2k_gemv_v2.asm','src/deep2/sovereign_q3k_gemv_v2.asm','src/deep2/sovereign_moe_fused.asm',
  'src/sampling/advanced_sampler.cpp','src/deep2/ProductionProfiler.cpp','src/deep2/BP16Streamer.cpp','src/deep2/ResidencyManager.cpp'
)
foreach ($f in $files) {
  $path = Join-Path 'F:\~dev\rawrxd' $f
  $exists = if (Test-Path $path) { 'EXISTS' } else { 'MISSING' }
  "$exists : $f"
}
