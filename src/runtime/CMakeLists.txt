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
)

# RawrXD Runtime Component
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
    ${RAWRXD_PREDICTIVE_MEMORY_SOURCES}
)

target_include_directories(rawrxd_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/memory
    ${CMAKE_CURRENT_SOURCE_DIR}/model_registry
    ${CMAKE_CURRENT_SOURCE_DIR}/session
    ${CMAKE_CURRENT_SOURCE_DIR}/router
    ${CMAKE_CURRENT_SOURCE_DIR}/cli
)

# Link against any required libraries
# target_link_libraries(rawxd_runtime PRIVATE ...)

# Set C++ standard
target_compile_features(rawrxd_runtime PRIVATE cxx_std_17)