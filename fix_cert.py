import re

import os
os.chdir(r'F:\~dev')

with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove stray endif() after certification_harness target_link_libraries
content = content.replace(
    '''target_link_libraries(certification_harness PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)\nendif()''',
    '''target_link_libraries(certification_harness PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)''')

# Now replace the whole certification_harness block
old_block = r'''# ============================================================================
# Certification Harness .+ Adversarial Evidence-Producing Benchmark Suite
# ============================================================================
add_executable\(certification_harness EXCLUDE_FROM_ALL
    certification/CertificationHarness\.cpp
    src/tokenizer/gguf_embedded_tokenizer\.cpp
    src/deep2/Deep2Engine\.cpp
    src/deep2/K2GlobalTensorIndex\.cpp
    src/deep2/GGUFLoader\.cpp
    src/deep2/ThreadPool\.cpp
    src/deep2/KVCache\.cpp
    src/deep2/QuantKernelRegistry\.cpp
    src/deep2/MoERouter\.cpp
    src/deep2/MoEWeightProxy\.cpp
    src/deep2/MoEEliminate\.cpp
    src/deep2/MoEWeightsLoader\.cpp
    src/deep2/DeepSeekMoELoader\.cpp
    src/deep2/TensorHop\.cpp
    src/deep2/MoEArchitectureParser\.cpp
    src/deep2/Deep2ExecutionGraph\.cpp
    src/deep2/ReverseHotpatchEngine\.cpp
    src/deep2/ReverseIntegration\.cpp
    src/deep2/DualGPUHook\.cpp
    src/deep2/ReverseTensorRecovery\.cpp
    src/deep2/StreamEngine\.cpp
    src/deep2/StreamRouter\.cpp
    src/deep2/FusedInferenceKernel\.cpp
    src/deep2/MedusaDecoder\.cpp
    src/deep2/WarmupScheduler\.cpp
    src/deep2/NUFusedPacker\.cpp
    src/deep2/CompressedKVCache\.cpp
    src/deep2/NVMeStream\.cpp
    src/deep2/SlidingWindowEngine\.cpp
    src/deep2/HotPatcher\.cpp
    src/deep2/HotPatcherSafety\.cpp
    src/deep2/AntiPatcher\.cpp
    src/deep2/TrailBrake\.cpp
    src/deep2/PatchCache\.cpp
    src/deep2/BottleTTL\.cpp
    src/deep2/GoalSystem\.cpp
    src/deep2/CPUFrequency\.cpp
    src/deep2/mars/VRAMManager\.cpp
    src/deep2/mars/TensorHotpatch\.cpp
    src/deep2/mars/DualGPUBackend\.cpp
    src/deep2/mars/MARSController\.cpp
    src/reverse/ReverseEngine\.cpp
    src/reverse/ReverseModelLoader\.cpp
    src/deep2/sovereign_deep2_kernels\.asm
    src/deep2/sovereign_q4k_gemv\.asm
    src/deep2/sovereign_q4k_gemv_v2\.asm
    src/deep2/sovereign_q2k_gemv_v2\.asm
    src/deep2/sovereign_q3k_gemv_v2\.asm
    src/deep2/sovereign_moe_fused\.asm
    src/sampling/advanced_sampler\.cpp
    src/deep2/ProductionProfiler\.cpp
    src/deep2/BP16Streamer\.cpp
    src/deep2/ResidencyManager\.cpp
\)
set_target_properties\(certification_harness PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY \$\{CMAKE_BINARY_DIR\}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded\$<\$<CONFIG:Debug>:Debug>"
\)
target_include_directories\(certification_harness PRIVATE
    \$\{CMAKE_SOURCE_DIR\}
    \$\{CMAKE_SOURCE_DIR\}/certification
    \$\{CMAKE_SOURCE_DIR\}/src
    \$\{CMAKE_SOURCE_DIR\}/src/deep2
    \$\{CMAKE_SOURCE_DIR\}/src/inference
    \$\{CMAKE_SOURCE_DIR\}/src/engine
    \$\{CMAKE_SOURCE_DIR\}/src/core
    \$\{CMAKE_SOURCE_DIR\}/src/codec
    \$\{CMAKE_SOURCE_DIR\}/include
    \$\{CMAKE_SOURCE_DIR\}/src/masm
    \$\{CMAKE_SOURCE_DIR\}/src/runtime/governance
    \$\{RAWR_VULKAN_INCLUDE\}
\)
target_link_libraries\(certification_harness PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
\)'''

new_block = '''# ============================================================================
# Certification Harness \u2013 Adversarial Evidence-Producing Benchmark Suite
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
    )
    set_target_properties(certification_harness PROPERTIES
        EXCLUDE_FROM_ALL TRUE
        EXCLUDE_FROM_DEFAULT_BUILD TRUE
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    target_include_directories(certification_harness PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/certification
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/inference
        ${CMAKE_SOURCE_DIR}/src/engine
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/codec
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src/masm
        ${CMAKE_SOURCE_DIR}/src/runtime/governance
        ${RAWR_VULKAN_INCLUDE}
    )
    target_link_libraries(certification_harness PRIVATE
        Threads::Threads
        kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
    )
else()
    message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] certification_harness skipped: no sources available")
endif()'''

content = re.sub(old_block, new_block, content, flags=re.DOTALL)

with open('rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.write(content)

print("certification_harness block replaced")
