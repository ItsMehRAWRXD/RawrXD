# ── Predictive Memory & Tensor Placement ─────────────────────────────────────
# Prediction decides what will probably be needed.
# Placement decides where it should live.
# Capacity decides whether it can live there.
# TransferScheduler moves it.
# ResidencyTracker records reality.
# TensorExecutionRouter executes it.
set(RAWRXD_PREDICTIVE_MEMORY_SOURCES
    memory/PlacementPolicy.cpp
    memory/ResidencyTracker.cpp
    memory/WorkingSetPredictor.cpp
    memory/CapacityManager.cpp
    memory/TransferScheduler.cpp
    memory/TensorPlacementManager.cpp
    memory/PredictiveMemoryManager.cpp
    memory/RouterPredictiveMemoryBridge.cpp
)

# RawrXD Runtime Component
# B002: TensorExecutionRouter.cpp added as the integration seam between the
# execution graph and the predictive-memory subsystem.  The router remains
# tier-agnostic; all placement decisions stay inside PredictiveMemoryManager.
add_library(rawrxd_runtime STATIC
    model_registry/model_manifest.cpp
    model_registry/model_registry.cpp
    session/inference_session.cpp
    session/session_manager.cpp
    router/task_classifier.cpp
    router/model_router.cpp
    cli/runtime_cli.cpp
    RuntimeContract.cpp
    RuntimeTypes.hpp
    CoreTypes.hpp
    LayerVersionRegistry.hpp
    LayerShadowExecutor.hpp
    TensorExecutionRouter.cpp
    ${RAWRXD_PREDICTIVE_MEMORY_SOURCES}
)

target_include_directories(rawrxd_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/memory
    ${CMAKE_CURRENT_SOURCE_DIR}/model_registry
    ${CMAKE_CURRENT_SOURCE_DIR}/session
    ${CMAKE_CURRENT_SOURCE_DIR}/router
    ${CMAKE_CURRENT_SOURCE_DIR}/cli
    # Needed so TensorExecutionRouter.cpp can find ../backend/vulkan_compute.h
    ${CMAKE_SOURCE_DIR}/src
)

# Build rawrxd_runtime without the full Vulkan stack so it compiles on any
# machine.  Targets that genuinely need Vulkan (Win32IDE, etc.) compile
# TensorExecutionRouter.cpp directly via their own source lists with the SDK.
target_compile_definitions(rawrxd_runtime PRIVATE RAWRXD_NO_VULKAN)

# Link against any required libraries
# target_link_libraries(rawrxd_runtime PRIVATE ...)

# Set C++ standard
target_compile_features(rawrxd_runtime PRIVATE cxx_std_17)

# ── Predictive-memory deterministic test (B002 functional gate) ───────────────
if(BUILD_TESTING OR RAWRXD_BUILD_RUNTIME_TESTS)
    add_executable(rawrxd_predictive_memory_test
        tests/predictive_memory_test.cpp
    )
    target_include_directories(rawrxd_predictive_memory_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/memory
    )
    target_link_libraries(rawrxd_predictive_memory_test PRIVATE rawrxd_runtime)
    target_compile_features(rawrxd_predictive_memory_test PRIVATE cxx_std_17)

    # B003 boundary test: execution loop owns predict/prefetch; router remains
    # a PMM consumer (ensureResident + dispatch + recordCompletion).
    add_executable(rawrxd_router_pmm_integration_test
        tests/router_pmm_integration_test.cpp
    )
    target_include_directories(rawrxd_router_pmm_integration_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/memory
    )
    target_link_libraries(rawrxd_router_pmm_integration_test PRIVATE rawrxd_runtime)
    target_compile_features(rawrxd_router_pmm_integration_test PRIVATE cxx_std_17)

    if(BUILD_TESTING)
        include(CTest)
        add_test(NAME rawrxd_predictive_memory_deterministic
                 COMMAND rawrxd_predictive_memory_test)
        add_test(NAME rawrxd_router_pmm_integration
                 COMMAND rawrxd_router_pmm_integration_test)
    endif()
endif()