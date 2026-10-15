$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# The issue is the nested if/else structure. Let me completely rewrite the section
# from the outer if (vulkan_compute.cpp) to its endif, making it flat.

# Find the outer if start
$outerIfStart = $content.IndexOf('if(EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.cpp AND EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.h)')
if ($outerIfStart -lt 0) {
    Write-Host "Outer if not found"
    exit 1
}

# Find the matching endif for the outer if
# We need to parse the nesting level
$searchStart = $outerIfStart
$nesting = 0
$outerIfEnd = -1
$i = $outerIfStart
while ($i -lt $content.Length) {
    $char = $content[$i]
    if ($content.Substring($i).StartsWith('if(')) {
        $nesting++
        $i += 2
        continue
    }
    if ($content.Substring($i).StartsWith('elseif(')) {
        $i += 5
        continue
    }
    if ($content.Substring($i).StartsWith('else()')) {
        if ($nesting == 1) {
            # This is the outer else
        }
        $i += 5
        continue
    }
    if ($content.Substring($i).StartsWith('endif()')) {
        $nesting--
        if ($nesting == 0) {
            $outerIfEnd = $i + 5  # include the endif()
            break
        }
        $i += 5
        continue
    }
    $i++
}

if ($outerIfEnd -lt 0) {
    Write-Host "Could not find outer endif"
    exit 1
}

Write-Host "Outer if: $outerIfStart to $outerIfEnd"

# Extract the outer if block
$outerBlock = $content.Substring($outerIfStart, $outerIfEnd - $outerIfStart)

# Now replace the entire outer block with a flattened version
# The new structure:
# if(vulkan_compute) {
#     rawrxd_gpu_compute target
#     deep2_engine_lib target (always created if Deep2Engine.cpp exists)
#     rawrxd_deep2_engine target
# } else() {
#     message(...)
# }

$newBlock = @"
if(EXISTS \${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.cpp AND EXISTS \${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.h)
    add_library(rawrxd_gpu_compute STATIC
        src/deep2/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
    )
    target_include_directories(rawrxd_gpu_compute PUBLIC
        \${CMAKE_SOURCE_DIR}/src
        # Must precede include/ so "vulkan_compute.h" resolves to the
        # Deep2::VulkanCompute definition this library implements.
        \${CMAKE_SOURCE_DIR}/src/deep2
        \${CMAKE_SOURCE_DIR}/include
    )
    if(TARGET ggml_interface)
        target_link_libraries(rawrxd_gpu_compute PUBLIC ggml_interface)
    endif()
    if(MSVC)
        target_compile_options(rawrxd_gpu_compute PRIVATE /EHsc /std:c++20 \$<\$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(rawrxd_gpu_compute PRIVATE -std=c++20 -fexceptions \$<\$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(rawrxd_gpu_compute PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS DEEP2_SHADER_DIR="\${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    message(STATUS "rawrxd_gpu_compute enabled: Deep2::VulkanCompute buildable from the main tree")

    # ------------------------------------------------------------------------
    # Deep2Engine: the engine that drives the GPU compute environment.
    # ------------------------------------------------------------------------
    if(EXISTS \${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp)
        # ------------------------------------------------------------------------
        # ENGINE_RECOVERY: the subsystems above were only ever compiled as a link
        # inventory, so their out-of-class implementations were never wired in.
        # The .cpp files below already exist in src/deep2/ and define the missing
        # symbols; they are added here so the engine links as a real executable
        # instead of enumerating what is absent. Each one is guarded on EXISTS so
        # a partially-recovered tree still configures.
        #
        # NOTE: src/deep2/execution_policy/ and src/deep2/mars/, plus
        # AttnCertProbe / SsmCertProbe / MlaCertProbe / Deep2DeviceManager /
        # Deep2MultiGpuLayerPlan / ElasticDynamicBudget / K2LivePolicy /
        # FusedLiveController / Deep2LivePath, are separate translation units
        # rather than header-only declarations.
        # ------------------------------------------------------------------------
        set(_DEEP2_ENGINE_SUBSYSTEM_SOURCES
            \${CMAKE_SOURCE_DIR}/src/deep2/KVCache.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/CompressedKVCache.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/NVMeStream.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/ResidencyManager.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/CycloneScheduler.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/SlidingWindowEngine.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/WarmupScheduler.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MARS.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/QuantKernelRegistry.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MoEWeightsLoader.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MoERouter.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MoEWeightProxy.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/NUFusedPacker.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/RouterPrefetchTelemetry.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/HotPatcher.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/ReverseHotpatchEngine.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/BP16Streamer.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/SovereignOutOfCoreRuntime.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Chamber.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/PlasmaGovernor.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2GlobalTensorIndex.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2GpuStreamCopy.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_GpuGemv.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2ShardIo.cpp
            # Certification probes (deep2/AttnCertProbe.cpp etc.)
            \${CMAKE_SOURCE_DIR}/src/deep2/AttnCertProbe.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/SsmCertProbe.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MlaCertProbe.cpp
            # Device manager + multi-GPU layer planning
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2DeviceManager.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2MultiGpuLayerPlan.cpp
            # Elastic residency budgeting (probe/derive/emit) and residency manager
            \${CMAKE_SOURCE_DIR}/src/deep2/ElasticDynamicBudget.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/ElasticResidencyManager.cpp
            # Live path + fused controller + K2 execution policy
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/FusedLiveController.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2LivePolicy.cpp
            # Cert probes / device manager (declared, definitions live in .cpp)
            \${CMAKE_SOURCE_DIR}/src/deep2/DualGPUHook.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/GhostCache.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/TrailBrake.cpp
            # MLA gating / Qa critical path / q-path device / logits lineage are
            # owned by K2MLA_FusedQ4KT.cpp / K2MLA_QaCritical.cpp /
            # K2MLA_QPathDevice.cpp / K2LogitsLineage.cpp (batch-05);
            # K2MLA_telemetry.cpp is intentionally NOT listed because it defines
            # the same symbols and would collide (LNK2005).
            # lavapath: free-token micro-zones + future consumer page ownership
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FreeTokenMicroZone.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FutureConsumerSpace.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicy.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicyApply.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicyStore.cpp
            # Ollama blob ingestion (declared in src/deep2/ollama_blob_parser.h)
            \${CMAKE_SOURCE_DIR}/src/deep2/ollama_blob_parser.cpp
            # Deep2Engine's own out-of-class members
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_missing_members.cpp
            # Sampling helpers used by the engine
            \${CMAKE_SOURCE_DIR}/src/sampling/advanced_sampler.cpp
            # ENGINE_RECOVERY batch-05: out-of-class definitions referenced by
            # the deep2 modules. mars/MARSController.cpp, mars/TensorHotpatch.cpp
            # and mars/DualGPUBackend.cpp are deliberately OMITTED (they redefine
            # MARSController members MARS.cpp already owns -> LNK2005).
            \${CMAKE_SOURCE_DIR}/src/deep2/KimiK2Config.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/ReverseTensorRecovery.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/mars/VRAMManager.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_FusedQ4KT.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_QaCritical.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_QPathDevice.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Gate.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2BraidExecutionPolicy.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/asm_stubs.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2LogitsLineage.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/GpuTransfer_Emit.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/MoEEliminate.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/engine_link_supplement.cpp
            # Pure-implementation out-of-class definitions (no main()). The
            # *_cert.cpp / *_parity.cpp harnesses are deliberately NOT listed
            # (each defines its own main()).
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FreeTokenMicroZone.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow_Acquire.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow_Emit.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Mech.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Mech.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Pinball.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Thermal.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_MechEnd.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2LivePolicy_Apply.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2MultiGpu_CostCut.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2GpuStreamCopy_Overlap.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/K2C1C9.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/StreamerParity_Post.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/StreamEngine.cpp            # Remaining CPUInference::VulkanCompute members: fused-layer
            # lifecycle, forward arena, GEMV staging, Q4_K/Q6_K dispatch and the
            # weight window. Forwards real Deep2::VulkanCompute capability and
            # fails closed where the implementation has none, so a false return
            # is a genuine "no device work happened" hand-off.
            \${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_adapter_fused.cpp
            # Patch safety: SHA-256, stack canary, crash recovery, pre-flight
            # and the RAII guards the hot-patcher constructs.
            \${CMAKE_SOURCE_DIR}/src/deep2/HotPatcherSafety.cpp
            # Completion for the two lavapath contracts that were left with a few
            # unimplemented members. Owns FindHotByKey/PickZone/EmitWitness and
            # ConsumerCount/NotePhysicalOverwrite only.
            \${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FreeTokenFutureCompletion.cpp
            # Stream engine lifecycle (ctor/dtor/Initialize/unreverseHot/
            # ReviveLayer/GetState). StreamEngine.cpp was simply not in the list.
            \${CMAKE_SOURCE_DIR}/src/deep2/StreamEngine.cpp
        )
        foreach(_s \${_DEEP2_ENGINE_SUBSYSTEM_SOURCES})
            if(NOT EXISTS "\${_s}")
                message(STATUS "rawrxd_deep2_engine: subsystem source absent, skipped: \${_s}")
            endif()
        endforeach()
        foreach(_s \${_DEEP2_ENGINE_SUBSYSTEM_SOURCES})
            if(NOT EXISTS "\${_s}")
                list(REMOVE_ITEM _DEEP2_ENGINE_SUBSYSTEM_SOURCES "\${_s}")
            endif()
        endforeach()

        # Create a static library from the engine subsystem sources so other targets
        # (deep2_gpu_decode_roofline, deep2_runtime_dispatch) can link against the
        # same implementation instead of re-listing sources and risking ODR violations.
        add_library(deep2_engine_lib STATIC
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            \${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            \${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
            \${_DEEP2_ENGINE_SUBSYSTEM_SOURCES}
        )
        target_include_directories(deep2_engine_lib PUBLIC
            \${CMAKE_SOURCE_DIR}/src
            \${CMAKE_SOURCE_DIR}/src/deep2
            \${CMAKE_SOURCE_DIR}/include
            \${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
            \${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
        )
        target_link_libraries(deep2_engine_lib PUBLIC
            rawrxd_gpu_compute
            ggml
            Vulkan::Vulkan
        )
        target_compile_options(deep2_engine_lib PRIVATE /EHsc /std:c++20 \$<\$<CONFIG:Release>:/O2>)
        target_compile_definitions(deep2_engine_lib PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS
            DEEP2_SHADER_DIR="\${CMAKE_SOURCE_DIR}/src/deep2/shaders"
        )
        set_target_properties(deep2_engine_lib PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY "\${CMAKE_BINARY_DIR}/Release"
        )

        # Main engine executable: contains the entry point and core engine logic,
        # links against the subsystem library.
        add_executable(rawrxd_deep2_engine
            \${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_dummy_main.cpp
        )
        target_link_libraries(rawrxd_deep2_engine PRIVATE deep2_engine_lib)
        set_target_properties(rawrxd_deep2_engine PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "\${CMAKE_BINARY_DIR}/bin"
        )

        message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")
    else()
        message(STATUS "rawrxd_deep2_engine EXCLUDED: src/deep2/Deep2Engine.cpp absent")
    endif()
else()
    message(STATUS "rawrxd_gpu_compute EXCLUDED: src/deep2/vulkan_compute.{h,cpp} absent")
endif()
"@

# Replace the outer block
$newContent = $content.Substring(0, $outerIfStart) + $newBlock + $content.Substring($outerIfEnd)
[System.IO.File]::WriteAllText("CMakeLists.txt", $newContent)
Write-Host "Replaced outer if block"