cmake_minimum_required(VERSION 3.20)
project(rawr_monolith LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Vulkan REQUIRED)

add_executable(rawr_monolith
    rawr_monolith_v2.cpp
    src/rawr_run_stream.cpp
    src/rawr_agent.cpp
    src/rawr_audit_state.cpp
    src/rawr_agent_dispatch.cpp
    src/rawr_stub_scan.cpp
    src/rawr_agent_audit_driver.cpp
    rawrxd/src/deep2/AgentToolAuthority.cpp
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
    rawrxd/src/deep2/Deep2Engine_GpuToken.cpp
    rawrxd/src/deep2/Deep2DeviceManager.cpp
    rawrxd/src/deep2/VramStreamingController.cpp
    rawrxd/src/deep2/StreamEngine.cpp
    rawrxd/src/deep2/StreamRouter.cpp
    rawrxd/src/deep2/BP16Streamer.cpp
    rawrxd/src/deep2/CompressedKVCache.cpp
    rawrxd/src/deep2/NVMeStream.cpp
    rawrxd/src/deep2/ElasticResidencyManager.cpp
    rawrxd/src/deep2/CycloneScheduler.cpp
    rawrxd/src/deep2/ProductionProfiler.cpp
    rawrxd/src/deep2/Chamber.cpp
    rawrxd/src/deep2/ToroidalKVCache.cpp
    rawrxd/src/deep2/PlasmaGovernor.cpp
    rawrxd/src/deep2/SovereignOutOfCoreRuntime.cpp
    rawrxd/src/deep2/expert_cache/ExpertCache.cpp
    rawrxd/src/deep2/expert_cache/VulkanExpertTransport.cpp
    rawrxd/src/deep2/expert_cache/HostStagingRing.cpp
    rawrxd/src/deep2/mars/MARSController.cpp
    rawrxd/src/deep2/streaming/ContinuousExecution.cpp
    rawrxd/src/deep2/streaming/Win32ContinuousBridge.cpp
    # Q2.5 link-authority repair. Deep2Engine.cpp / Deep2Engine_SsVkDecodeBind.cpp /
    # Deep2Engine_GpuForward.cpp reference symbols whose definitions live in these
    # translation units. They were listed ONLY in the deep2_benchmark target, so
    # rawr_monolith compiled every object and then failed at link with 20 LNK2019s.
    # A compile-clean target that cannot link is not a passing target.
    rawrxd/src/deep2/Beaconism.cpp
    rawrxd/src/deep2/GpuScheduler.cpp
    rawrxd/src/deep2/TimeReverseDigest.cpp
    rawrxd/src/deep2/ModelRegistry.cpp
    rawrxd/src/deep2/Deep2PredictiveRouter.cpp
    rawrxd/src/deep2/streaming/EventLedger.cpp
    rawrxd/src/deep2/lavapath/DualStickEnvSnap.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow_Acquire.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow_Emit.cpp
    src/deep2/Classify.asm
    rawrxd/src/rawr_classifier_scalar.asm
    rawrxd/src/rawr_classifier_avx2.asm
)

target_include_directories(rawr_monolith PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2/streaming
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(rawr_monolith PRIVATE
    RAWR_MONOLITH_STANDALONE
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWR_HAS_RAWR_INFERENCE=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(rawr_monolith PRIVATE
    /arch:AVX512
    /fp:fast
)

if(MSVC)
    target_compile_options(rawr_monolith PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(rawr_monolith PRIVATE Vulkan::Vulkan)

# ---- V2 static library target ----
add_library(rawrxd_screenpilot_e2e STATIC
    rawrxd/src/screenpilot/rawrxd_screenpilot_agent_v2.cpp
)

target_include_directories(rawrxd_screenpilot_e2e PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/include/screenpilot
)

target_compile_features(rawrxd_screenpilot_e2e PUBLIC cxx_std_20)
target_compile_definitions(rawrxd_screenpilot_e2e PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(rawrxd_screenpilot_e2e PUBLIC bcrypt)

if(MSVC)
    target_compile_options(rawrxd_screenpilot_e2e PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(rawr_monolith PRIVATE rawrxd_screenpilot_e2e)

# ---- Deep2 core translation units ----
#
# RAWRXD_GATE_TARGET_GHOST_001
#
# qwen32_85tps_gate.exe existed at build_p2/Debug/ (2026-09-17,
# SHA256 2F0DD9329F1ADAE5D52E4A0D575067CC50E908CDCC36476825B66431CFA1086B)
# and was cited as evidence for the 85 TPS ladder. It was built from a CMake
# target that was NEVER COMMITTED:
#
#   git log -S 'qwen32_85tps_gate' -- CMakeLists.txt   ->  no commits, ever
#   git ls-files build_p2/                            ->  untracked
#
# The generator input was untracked, so the exe could not be reproduced, could
# not be tied to a source identity, and could not be symbolized. Every receipt
# derived from it described a build graph that no longer exists. That is the
# same defect class as the QKV_CPU_FALLBACK ghost: a real artifact, a real
# measurement, and no way to name the code that produced it.
#
# The target is defined here so the gate is buildable FROM A TRACKED SOURCE
# IDENTITY. The source list is shared rather than duplicated: deep2_benchmark and
# the gate need the same Deep2 objects, and a private copy of a 40-entry list is
# precisely how the two drift apart until one of them cannot link.
set(RAWRXD_DEEP2_CORE_SOURCES
    rawrxd/src/deep2/AgentToolAuthority.cpp
    rawrxd/src/deep2/Deep2Engine.cpp
    rawrxd/src/deep2/Deep2Engine_Speculative.cpp
    rawrxd/src/deep2/Tokenizer.cpp
    rawrxd/src/deep2/Sampler.cpp
    rawrxd/src/deep2/QuantKernelRegistry.cpp
    rawrxd/src/deep2/Deep2Engine_SsVkDecodeBind.cpp
    rawrxd/src/deep2/vulkan_compute.cpp
    rawrxd/src/deep2/Deep2Engine_VulkanRuntime.cpp
    rawrxd/src/deep2/Deep2Engine_GpuForward.cpp
    rawrxd/src/deep2/Deep2MultiGpuLayerPlan.cpp
    rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
    rawrxd/src/deep2/Deep2Engine_GpuMoEMLA.cpp
    rawrxd/src/deep2/Deep2Engine_GpuToken.cpp
    rawrxd/src/deep2/Deep2DeviceManager.cpp
    rawrxd/src/deep2/VramStreamingController.cpp
    rawrxd/src/deep2/StreamEngine.cpp
    rawrxd/src/deep2/StreamRouter.cpp
    rawrxd/src/deep2/BP16Streamer.cpp
    rawrxd/src/deep2/CompressedKVCache.cpp
    rawrxd/src/deep2/NVMeStream.cpp
    rawrxd/src/deep2/ElasticResidencyManager.cpp
    rawrxd/src/deep2/CycloneScheduler.cpp
    rawrxd/src/deep2/ProductionProfiler.cpp
    rawrxd/src/deep2/Chamber.cpp
    rawrxd/src/deep2/ToroidalKVCache.cpp
    rawrxd/src/deep2/PlasmaGovernor.cpp
    rawrxd/src/deep2/SovereignOutOfCoreRuntime.cpp
    rawrxd/src/deep2/expert_cache/ExpertCache.cpp
    rawrxd/src/deep2/expert_cache/VulkanExpertTransport.cpp
    rawrxd/src/deep2/expert_cache/HostStagingRing.cpp
    rawrxd/src/deep2/mars/MARSController.cpp
    rawrxd/src/deep2/streaming/ContinuousExecution.cpp
    rawrxd/src/deep2/streaming/Win32ContinuousBridge.cpp
    rawrxd/src/deep2/Beaconism.cpp
    rawrxd/src/deep2/GpuScheduler.cpp
    rawrxd/src/deep2/TimeReverseDigest.cpp
    rawrxd/src/deep2/ModelRegistry.cpp
    # RAWRXD_B66_LINK_AUTHORITY_001: Deep2Engine::loadModel calls
    # B66RuntimeMetaBinder::bind, defined at Deep2B66RuntimeMeta.cpp:19. Omitting
    # it compiles every TU clean and then fails at link with LNK2019 -- the
    # target looks healthy right up to the point where it cannot be produced.
    # This is the same link-authority defect the Q2.5 comments above describe,
    # and it was still live in both targets built from this list.
    rawrxd/src/deep2/Deep2B66RuntimeMeta.cpp
    # RAWRXD_INFERENCE_WIRE_001: Deep2Engine.cpp calls WireRecordDispatch at the
    # layer-dispatch boundary, so this TU must be in every target that links the
    # engine. Omitting it reproduces exactly the LNK2019 class documented above.
    rawrxd/src/deep2/InferenceWire.cpp
    rawrxd/src/deep2/Deep2PredictiveRouter.cpp
    rawrxd/src/deep2/streaming/EventLedger.cpp
    rawrxd/src/deep2/lavapath/DualStickEnvSnap.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow_Acquire.cpp
    rawrxd/src/deep2/lavapath/DualStickStreamWindow_Emit.cpp
    src/deep2/Classify.asm
    rawrxd/src/rawr_classifier_scalar.asm
    rawrxd/src/rawr_classifier_avx2.asm
)

# ---- Deep2 benchmark target ----
add_executable(deep2_benchmark
    rawrxd/src/deep2/deep2_benchmark_main.cpp
    # Shared with qwen32_85tps_gate below. deep2_benchmark adds exactly one TU:
    # the strict-GPU violation counter definitions.
    ${RAWRXD_DEEP2_CORE_SOURCES}
    rawrxd/src/deep2/strict_gpu_violations.cpp
)

# ---- 85 TPS ladder gate ----
#
# tests/qwen32_85tps_gate.cpp is tracked at f66d63e05 and was previously
# unbuildable: no target referenced it. It is the ladder the 85 TPS claim rests
# on, and every artifact attributed to it came from an untracked generator input.
#
# /DEBUG:FULL + /DEBUG is not cosmetic here. It is the difference between a
# fault offset and a fault source. The MLA fast-fail investigation was stuck at
# RVA 0xC3139/0xC3134 because no symbol existed for the image; a Debug/FullOpt
# binary with a matching PDB closes that class of question permanently.
add_executable(qwen32_85tps_gate
    tests/qwen32_85tps_gate.cpp
    ${RAWRXD_DEEP2_CORE_SOURCES}
    # NOTE: strict_gpu_violations.cpp is deliberately NOT listed.
    # tests/qwen32_85tps_gate.cpp:12 defines g_strictGpuViolations itself and the
    # engine increments that same symbol (Deep2Engine_Speculative.cpp:11 declares
    # it extern; 407/482/505/522 increment it). Listing both definitions is
    # LNK2005. The gate's own definition satisfies the engine's reference, which
    # is the correct owner: the counter is the gate's verdict input, not a library
    # global that outlives it.
)

target_include_directories(qwen32_85tps_gate PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2/streaming
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(qwen32_85tps_gate PRIVATE
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWR_HAS_RAWR_INFERENCE=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(qwen32_85tps_gate PRIVATE
    /arch:AVX512
    /fp:fast
    /Zi
    /DEBUG:FULL
)

if(MSVC)
    target_compile_options(qwen32_85tps_gate PRIVATE /W4 /permissive- /EHsc)
    target_link_options(qwen32_85tps_gate PRIVATE /DEBUG)
endif()

target_link_libraries(qwen32_85tps_gate PRIVATE Vulkan::Vulkan)

# ---- RAWRXD_INFERENCE_WIRE_001 ----
#
# The wire protocol and its falsification probe. Deliberately a STANDALONE
# target: it links no engine object, so it cannot inherit a dependency on the
# very runtime it is meant to observe. If the probe needed Deep2 to run, a Deep2
# defect could masquerade as a wire defect.
#
# Excluded from `all`; request it explicitly.
add_executable(inference_wire_001 EXCLUDE_FROM_ALL
    rawrxd/certs/inference_wire_001.cpp
    rawrxd/src/deep2/InferenceWire.cpp
)

target_include_directories(inference_wire_001 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

target_compile_options(inference_wire_001 PRIVATE /O2 /W4 /permissive- /EHsc)

if(MSVC)
    target_compile_options(inference_wire_001 PRIVATE /Zi /DEBUG:FULL)
    target_link_options(inference_wire_001 PRIVATE /DEBUG)
endif()

# ---- RAWRXD_LAYER0_AUTHORITY_001 ----
#
# The layer over Layer 0: in-process exception capture, so a fault's registers
# and fast-fail sub-code are observed from inside the program that faulted --
# no cdb, no dump, and no reverse-engineering of the CRT fast-fail table out of
# the instruction stream.
#
# Standalone like the wire: it links no engine object, so an engine defect cannot
# masquerade as a capture defect, and the guard is proven before anything
# depends on it.
add_executable(layer0_authority_001 EXCLUDE_FROM_ALL
    rawrxd/certs/layer0_authority_001.cpp
    rawrxd/src/deep2/Layer0Guard.cpp
)

target_include_directories(layer0_authority_001 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
)

target_compile_options(layer0_authority_001 PRIVATE /O2 /W3 /permissive- /EHsc)

if(MSVC)
    target_compile_options(layer0_authority_001 PRIVATE /Zi /DEBUG:FULL /utf-8)
    target_link_options(layer0_authority_001 PRIVATE /DEBUG)
endif()

# /FS is not optional here. With /Zi, MSBuild's multi-processor build hands the
# same intermediate PDB to several CL.EXE processes, and a leftover compiler
# from an earlier build makes that a C1041 "cannot open program database". /FS
# serialises PDB access through mspdbsrv. The failure is invisible in a clean
# single-lane build and appears only under concurrency, which is why it is set
# permanently rather than worked around with /m:1.
target_compile_options(layer0_authority_001 PRIVATE /FS)

target_link_libraries(layer0_authority_001 PRIVATE bcrypt)

# ---- RAWRXD_RESIDUAL_OVERLAY_FUSION_001 ----
#
# Proof harness only. Links no engine object: there is no working GPU forward
# lane to attach a fusion kernel to yet (Deep2Engine.cpp:5407 dual-row host
# lane), so a target that linked Deep2 would certify a path nothing reaches.
#
# Deliberately EXCLUDE_FROM_ALL so it does not become a build-graph citizen that
# gets stubbed out and reported as a subsystem. Its verdict is about arithmetic,
# and it must be run deliberately.
add_executable(residual_overlay_fusion_001 EXCLUDE_FROM_ALL
    rawrxd/tools/residual_overlay_fusion_001.cpp
)

target_compile_options(residual_overlay_fusion_001 PRIVATE
    /std:c++17 /EHsc /O2 /W3 /utf-8
)

if(MSVC)
    target_compile_options(residual_overlay_fusion_001 PRIVATE /FS)
endif()

# ---- RAWRXD_RESIDUAL_OVERLAY_SWEEP_001 ----
#
# Sweeps the base quantizer over levels x group_size to locate the Pareto
# frontier, and measures the one quantity the single-point receipt declared
# UNMEASURED: whether the delta is COMPRESSIBLE, not merely large.
#
# Deliberately re-implements the quantizer instead of including the other lane's
# harness, because that file is untracked and owned elsewhere. Two quantizers
# could disagree, so CONTROL 0 reproduces that harness's published single point
# (rel_L2 0.734019, delta ratio 0.786882) and refuses to report the sweep unless
# it matches -- agreement is proven, not assumed.
add_executable(residual_overlay_sweep_001 EXCLUDE_FROM_ALL
    rawrxd/certs/residual_overlay_sweep_001.cpp
)

target_compile_options(residual_overlay_sweep_001 PRIVATE
    /std:c++17 /EHsc /O2 /W3 /utf-8
)

if(MSVC)
    target_compile_options(residual_overlay_sweep_001 PRIVATE /FS)
endif()

# ---- RAWRXD_GGUF_TENSOR_SLICE_001 ----
#
# Minimal self-validating GGUF reader. Exists because the in-tree loader cannot
# supply a real weight tensor: src/deep2/GGUFLoader.cpp is 35 bytes (emptied by
# commit 964eed96f) and no target builds a GGUF-reading probe, so every
# quantisation measurement so far has been made on SYNTHETIC weights.
#
# Reads one quant block from one tensor. No whole-file copy, no engine, no
# Vulkan. Dequantisation is deliberately NOT done here: a wrong dequantiser
# would silently corrupt every result computed on top of it, so it is a separate
# stage with its own validation.
add_executable(gguf_tensor_slice_001 EXCLUDE_FROM_ALL
    rawrxd/certs/gguf_tensor_slice_001.cpp
)

target_compile_options(gguf_tensor_slice_001 PRIVATE
    /std:c++17 /EHsc /O2 /W3 /utf-8
)

if(MSVC)
    target_compile_options(gguf_tensor_slice_001 PRIVATE /FS)
endif()

target_include_directories(deep2_benchmark PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2
    ${CMAKE_CURRENT_SOURCE_DIR}/rawrxd/src/deep2/streaming
    ${Vulkan_INCLUDE_DIRS}
)

target_compile_definitions(deep2_benchmark PRIVATE
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWR_HAS_RAWR_INFERENCE=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(deep2_benchmark PRIVATE
    /arch:AVX512
    /fp:fast
)

if(MSVC)
    target_compile_options(deep2_benchmark PRIVATE /W4 /permissive- /EHsc)
endif()

target_link_libraries(deep2_benchmark PRIVATE Vulkan::Vulkan)
