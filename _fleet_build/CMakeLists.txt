cmake_minimum_required(VERSION 3.20)
project(fleet_gate_standalone CXX)

# RAWRXD_LOCAL_AGENT_FLEET_001 standalone build scaffold.
# Links the N1-certified strict InferenceEngine.lib; avoids the mangled
# production CMakeLists tree entirely.

set(RAWRXD "F:/~dev/rawrxd" CACHE PATH "RawrXD source root")
set(ENGINE_LIB "F:/~dev/rawrxd/build_clean_n1/Release/InferenceEngine.lib" CACHE FILEPATH "Certified engine library")
set(VULKAN_SDK "C:/VulkanSDK/1.4.357.0" CACHE PATH "Vulkan SDK root")

add_executable(fleet_gate "${RAWRXD}/tests/fleet_gate.cpp")

# Q4K_VEC_DOT_PARITY_001 / DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic:
# tokenizes the oracle prompt and prints the token ids.
add_executable(tok_probe "${RAWRXD}/tests/tok_probe.cpp")
target_include_directories(tok_probe PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
target_link_libraries(tok_probe PRIVATE "${ENGINE_LIB}")
set_target_properties(tok_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(tok_probe PRIVATE /EHsc /W3 /O2)

add_executable(qwen2_oracle_gate "${RAWRXD}/tests/qwen2_oracle_gate.cpp")
target_include_directories(qwen2_oracle_gate PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
if(EXISTS "${VULKAN_SDK}/Include/vulkan/vulkan.h")
    target_include_directories(qwen2_oracle_gate PRIVATE "${VULKAN_SDK}/Include")
endif()
target_link_libraries(qwen2_oracle_gate PRIVATE "${ENGINE_LIB}" dxgi)
if(EXISTS "${VULKAN_SDK}/Lib/vulkan-1.lib")
    target_link_libraries(qwen2_oracle_gate PRIVATE "${VULKAN_SDK}/Lib/vulkan-1.lib")
endif()
set_target_properties(qwen2_oracle_gate PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(qwen2_oracle_gate PRIVATE /EHsc /W3 /O2)

add_executable(q6k_kernel_parity_test "${RAWRXD}/tests/q6k_kernel_parity_test.cpp")
target_include_directories(q6k_kernel_parity_test PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
if(EXISTS "${VULKAN_SDK}/Include/vulkan/vulkan.h")
    target_include_directories(q6k_kernel_parity_test PRIVATE "${VULKAN_SDK}/Include")
endif()
target_link_libraries(q6k_kernel_parity_test PRIVATE "${ENGINE_LIB}" dxgi)
if(EXISTS "${VULKAN_SDK}/Lib/vulkan-1.lib")
    target_link_libraries(q6k_kernel_parity_test PRIVATE "${VULKAN_SDK}/Lib/vulkan-1.lib")
endif()
set_target_properties(q6k_kernel_parity_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(q6k_kernel_parity_test PRIVATE /EHsc /W3 /O2)

add_executable(q4k_kernel_parity_test "${RAWRXD}/tests/q4k_kernel_parity_test.cpp")
target_include_directories(q4k_kernel_parity_test PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
if(EXISTS "${VULKAN_SDK}/Include/vulkan/vulkan.h")
    target_include_directories(q4k_kernel_parity_test PRIVATE "${VULKAN_SDK}/Include")
endif()
target_link_libraries(q4k_kernel_parity_test PRIVATE "${ENGINE_LIB}" dxgi)
if(EXISTS "${VULKAN_SDK}/Lib/vulkan-1.lib")
    target_link_libraries(q4k_kernel_parity_test PRIVATE "${VULKAN_SDK}/Lib/vulkan-1.lib")
endif()
set_target_properties(q4k_kernel_parity_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(q4k_kernel_parity_test PRIVATE /EHsc /W3 /O2)

add_executable(q4k_vecdot_parity_gate "${RAWRXD}/tests/q4k_vecdot_parity_gate.cpp")
target_include_directories(q4k_vecdot_parity_gate PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
if(EXISTS "${VULKAN_SDK}/Include/vulkan/vulkan.h")
    target_include_directories(q4k_vecdot_parity_gate PRIVATE "${VULKAN_SDK}/Include")
endif()
target_link_libraries(q4k_vecdot_parity_gate PRIVATE "${ENGINE_LIB}" dxgi)
if(EXISTS "${VULKAN_SDK}/Lib/vulkan-1.lib")
    target_link_libraries(q4k_vecdot_parity_gate PRIVATE "${VULKAN_SDK}/Lib/vulkan-1.lib")
endif()
set_target_properties(q4k_vecdot_parity_gate PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(q4k_vecdot_parity_gate PRIVATE /EHsc /W3 /O2)

target_include_directories(fleet_gate PRIVATE
    "${RAWRXD}"
    "${RAWRXD}/include"
    "${RAWRXD}/src"
    "${RAWRXD}/src/deep2"
    "${RAWRXD}/include/core"
)
if(EXISTS "${VULKAN_SDK}/Include/vulkan/vulkan.h")
    target_include_directories(fleet_gate PRIVATE "${VULKAN_SDK}/Include")
endif()

target_link_libraries(fleet_gate PRIVATE "${ENGINE_LIB}" dxgi)

set_target_properties(fleet_gate PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
target_compile_options(fleet_gate PRIVATE /EHsc /W3 /O2)