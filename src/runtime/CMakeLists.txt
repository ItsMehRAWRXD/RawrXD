# RawrXD Runtime Component
add_library(rawrxd_runtime STATIC
    model_registry/model_manifest.cpp
    model_registry/model_registry.cpp
    session/inference_session.cpp
    session/session_manager.cpp
    router/task_classifier.cpp
    router/model_router.cpp
    cli/runtime_cli.cpp
    main.cpp
    test_runtime.cpp
)

target_include_directories(rawrxd_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/model_registry
    ${CMAKE_CURRENT_SOURCE_DIR}/session
    ${CMAKE_CURRENT_SOURCE_DIR}/router
    ${CMAKE_CURRENT_SOURCE_DIR}/cli
)

# Link against any required libraries
# target_link_libraries(rawxd_runtime PRIVATE ...)

# Set C++ standard
target_compile_features(rawxd_runtime PRIVATE cxx_std_17)