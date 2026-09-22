import re

with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Certification harness: convert inline list to variable + filter + guard
old_cert = """# ============================================================================
# Certification Harness \u00ce\u00a9 Adversarial Evidence-Producing Benchmark Suite
# ============================================================================
add_executable(certification_harness EXCLUDE_FROM_ALL
    certification/CertificationHarness.cpp
    src/tokenizer/gguf_embedded_tokenizer.cpp
    src/deep2/Deep2Engine.cpp
    src/deep2/K2GlobalTensorIndex.cpp
    src/deep2/GGUFLoader.cpp
    src/deep2/ThreadPool.cpp
    src/deep2/KVCache.cpp
    src/deep2/QuantKernelRegistry.cpp
    src/deep2/MoERouter.cpp
    src/deep2/MoEWeightProxy.cpp
    src/deep2/MoEEliminate.cpp
    src/deep2/MoEWeightsLoader.cpp
    src/deep2/DeepSeekMoELoader.cpp
    src/deep2/TensorHop.cpp
    src/deep2/MoEArchitectureParser.cpp
    src/deep2/Deep2ExecutionGraph.cpp
    src/deep2/ReverseHotpatchEngine.cpp
    src/deep2/ReverseIntegration.cpp
    src/deep2/DualGPUHook.cpp
    src/deep2/ReverseTensorRecovery.cpp
    src/deep2/StreamEngine.cpp
    src/deep2/StreamRouter.cpp
    src/deep2/FusedInferenceKernel.cpp
    src/deep2/MedusaDecoder.cpp
    src/deep2/WarmupScheduler.cpp
    src/deep2/NUFusedPacker.cpp
    src/deep2/CompressedKVCache.cpp
    src/deep2/NVMeStream.cpp
    src/deep2/SlidingWindowEngine.cpp
    src/deep2/HotPatcher.cpp
    src/deep2/HotPatcherSafety.cpp
    src/deep2/AntiPatcher.cpp
    src/deep2/TrailBrake.cpp
    src/deep2/PatchCache.cpp
    src/deep2/BottleTTL.cpp
    src/deep2/GoalSystem.cpp
    src/deep2/CPUFrequency.cpp
    src/deep2/mars/VRAMManager.cpp
    src/deep2/mars/TensorHotpatch.cpp
    src/deep2/mars/DualGPUBackend.cpp
    src/deep2/mars/MARSController.cpp
    src/reverse/ReverseEngine.cpp
    src/reverse/ReverseModelLoader.cpp
    src/deep2/sovereign_deep2_kernels.asm
    src/deep2/sovereign_q4k_gemv.asm
    src/deep2/sovereign_q4k_gemv_v2.asm
    src/deep2/sovereign_q2k_gemv_v2.asm
    src/deep2/sovereign_q3k_gemv_v2.asm
    src/deep2/sovereign_moe_fused.asm
    src/sampling/advanced_sampler.cpp
    src/deep2/ProductionProfiler.cpp
    src/deep2/BP16Streamer.cpp
    src/deep2/ResidencyManager.cpp
)"""

new_cert = """# ============================================================================
# Certification Harness \u00ce\u00a9 Adversarial Evidence-Producing Benchmark Suite
# ============================================================================
set(CERTIFICATION_HARNESS_SOURCES
    certification/CertificationHarness.cpp
    src/tokenizer/gguf_embedded_tokenizer.cpp
    src/deep2/Deep2Engine.cpp
    src/deep2/K2GlobalTensorIndex.cpp
    src/deep2/GGUFLoader.cpp
    src/deep2/ThreadPool.cpp
    src/deep2/KVCache.cpp
    src/deep2/QuantKernelRegistry.cpp
    src/deep2/MoERouter.cpp
    src/deep2/MoEWeightProxy.cpp
    src/deep2/MoEEliminate.cpp
    src/deep2/MoEWeightsLoader.cpp
    src/deep2/DeepSeekMoELoader.cpp
    src/deep2/TensorHop.cpp
    src/deep2/MoEArchitectureParser.cpp
    src/deep2/Deep2ExecutionGraph.cpp
    src/deep2/ReverseHotpatchEngine.cpp
    src/deep2/ReverseIntegration.cpp
    src/deep2/DualGPUHook.cpp
    src/deep2/ReverseTensorRecovery.cpp
    src/deep2/StreamEngine.cpp
    src/deep2/StreamRouter.cpp
    src/deep2/FusedInferenceKernel.cpp
    src/deep2/MedusaDecoder.cpp
    src/deep2/WarmupScheduler.cpp
    src/deep2/NUFusedPacker.cpp
    src/deep2/CompressedKVCache.cpp
    src/deep2/NVMeStream.cpp
    src/deep2/SlidingWindowEngine.cpp
    src/deep2/HotPatcher.cpp
    src/deep2/HotPatcherSafety.cpp
    src/deep2/AntiPatcher.cpp
    src/deep2/TrailBrake.cpp
    src/deep2/PatchCache.cpp
    src/deep2/BottleTTL.cpp
    src/deep2/GoalSystem.cpp
    src/deep2/CPUFrequency.cpp
    src/deep2/mars/VRAMManager.cpp
    src/deep2/mars/TensorHotpatch.cpp
    src/deep2/mars/DualGPUBackend.cpp
    src/deep2/mars/MARSController.cpp
    src/reverse/ReverseEngine.cpp
    src/reverse/ReverseModelLoader.cpp
    src/deep2/sovereign_deep2_kernels.asm
    src/deep2/sovereign_q4k_gemv.asm
    src/deep2/sovereign_q4k_gemv_v2.asm
    src/deep2/sovereign_q2k_gemv_v2.asm
    src/deep2/sovereign_q3k_gemv_v2.asm
    src/deep2/sovereign_moe_fused.asm
    src/sampling/advanced_sampler.cpp
    src/deep2/ProductionProfiler.cpp
    src/deep2/BP16Streamer.cpp
    src/deep2/ResidencyManager.cpp
)
rawrxd_filter_missing_sources(CERTIFICATION_HARNESS_SOURCES)
if(CERTIFICATION_HARNESS_SOURCES)
    add_executable(certification_harness EXCLUDE_FROM_ALL
        ${CERTIFICATION_HARNESS_SOURCES}
    )"""

content = content.replace(old_cert, new_cert)

# Find and close the certification_harness block with endif()
# After add_executable(certification_harness...) there is set_target_properties(certification_harness ...)
# We need to wrap set_target_properties and target_* inside the if(CERTIFICATION_HARNESS_SOURCES)
# The block ends at target_link_libraries(certification_harness PRIVATE ...)
# then an if(DEFINED _WIN10_SDK_ROOT...) block, then endif() for the WIN10 SDK.
# We need to insert endif() after the last target_link_libraries or after the WIN10 SDK block.

# Let me find the certification_harness target_link_libraries block
cert_end_pattern = r"(target_link_libraries\(certification_harness PRIVATE\n    Threads::Threads\n    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi\n\))"
content = re.sub(cert_end_pattern, r"\1endif()\n", content)

print("certification_harness fix applied")

with open('rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.write(content)
print("Saved")
