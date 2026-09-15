# Tools - Command-line utilities for benchmarking and testing
# These targets require InferenceEngine, ggml, and Qt — skip if any are missing

set(_TOOLS_CAN_BUILD TRUE)
if(NOT TARGET InferenceEngine)
    set(_TOOLS_CAN_BUILD FALSE)
endif()
if(NOT TARGET ggml)
    set(_TOOLS_CAN_BUILD FALSE)
endif()

if(_TOOLS_CAN_BUILD)
# Simple GPU Test - For hotpatch testing framework
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/simple_gpu_test.cpp")
add_executable(simple_gpu_test
    simple_gpu_test.cpp
)
target_link_libraries(simple_gpu_test PRIVATE InferenceEngine ggml)
endif()

# Real Multi-Model Benchmark - For comprehensive model testing
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/real_multi_model_benchmark.cpp")
add_executable(real_multi_model_benchmark
    real_multi_model_benchmark.cpp
)
target_link_libraries(real_multi_model_benchmark PRIVATE InferenceEngine ggml)
endif()

# GGUF API Server - Real HTTP API with GPU inference
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../gguf_api_server.cpp")
add_executable(gguf_api_server
    ../gguf_api_server.cpp
)
target_link_libraries(gguf_api_server PRIVATE InferenceEngine ggml ws2_32)
endif()
endif()

if(TARGET gguf_api_server)
target_include_directories(gguf_api_server PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Install targets
install(TARGETS simple_gpu_test real_multi_model_benchmark gguf_api_server
    RUNTIME DESTINATION bin
)
endif()
