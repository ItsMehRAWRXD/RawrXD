cmake_minimum_required(VERSION 3.16)
project(SEG VERSION 1.0.0 LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Source files
# ============================================================================
set(SEG_SOURCES
    seg_node.cpp
    seg_graph.cpp
    seg_scheduler.cpp
    seg_memory.cpp
    seg_executor.cpp
    seg_agent.cpp
    seg_runtime.cpp
    seg_models.cpp
    seg_telemetry_view.cpp
    # Phase B.4: Sovereign Execution Graph Core
    ../src/seg/SovereignExecutionGraph.cpp
)

set(SEG_HEADERS
    seg_node.hpp
    seg_graph.hpp
    seg_scheduler.hpp
    seg_memory.hpp
    seg_executor.hpp
    seg_agent.hpp
    seg_runtime.hpp
    seg_models.hpp
    seg_telemetry_view.hpp
    # Phase B.4: Sovereign Execution Graph Core
    ../src/seg/SovereignExecutionGraph.hpp
)

# ============================================================================
# Runtime Sources (shared with RawrXD)
# ============================================================================
set(RUNTIME_SOURCES
    ../runtime/streaming_multi_layer_backend.cpp
    ../runtime/streaming_gguf_loader.cpp
    ../runtime/streaming_layer_registry.cpp
    ../runtime/kv_cache.cpp
    ../runtime/q4k_decoder.cpp
    ../runtime/telemetry_stub.cpp
)

set(RUNTIME_HEADERS
    ../runtime/streaming_multi_layer_backend.hpp
    ../runtime/streaming_gguf_loader.hpp
    ../runtime/streaming_layer_registry.hpp
    ../runtime/kv_cache.hpp
    ../runtime/q4k_decoder.hpp
    ../runtime/telemetry_masm_bridge.hpp
    ../runtime/telemetry_ids.hpp
)

# ============================================================================
# MASM Telemetry Core (x64 only) - DISABLED for Phase B.4
# Re-enable after SEG core validation
# ============================================================================
# if(CMAKE_SIZEOF_VOID_P EQUAL 8)
#     enable_language(ASM_MASM)
#     set(TELEMETRY_SOURCES
#         ../runtime/telemetry_masm.asm
#     )
# else()
#     message(FATAL_ERROR "x86 build not supported. Use x64.")
# endif()
set(TELEMETRY_SOURCES "")

# ============================================================================
# Create library
# ============================================================================
add_library(seg STATIC
    ${SEG_SOURCES}
    ${SEG_HEADERS}
    ${RUNTIME_SOURCES}
    ${RUNTIME_HEADERS}
    ${TELEMETRY_SOURCES}
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(seg PRIVATE _WIN32_WINNT=0x0A00)
    target_link_libraries(seg PRIVATE)
else()
    target_link_libraries(seg PRIVATE pthread)
endif()

# Include directories
target_include_directories(seg PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Compiler options
if(MSVC)
    target_compile_options(seg PRIVATE /W4 /WX- /O2 /arch:AVX2)
    target_compile_options(seg PRIVATE /EHsc)
else()
    target_compile_options(seg PRIVATE -Wall -Wextra -O3 -march=native)
endif()

# Optional: MASM integration
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../masm_kernels")
    # Link MASM object files if present
    file(GLOB MASM_OBJS "${CMAKE_CURRENT_SOURCE_DIR}/../masm_kernels/*.obj")
    if(MASM_OBJS)
        target_sources(seg PRIVATE ${MASM_OBJS})
        message(STATUS "Found MASM kernels: ${MASM_OBJS}")
    endif()
endif()

# Example executable
add_executable(seg_example example.cpp)
target_link_libraries(seg_example PRIVATE seg)

# Install
install(TARGETS seg seg_example
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${SEG_HEADERS} DESTINATION include/seg)
