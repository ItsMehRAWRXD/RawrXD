# =============================================================================
# RawrXD-CoreRuntime Target Definition
# =============================================================================
# PURPOSE: Isolate core inference engine from UI/IDE contamination
# RULE: If it doesn't run a model → graph → execution → memory loop, it's OUT
# =============================================================================

set(CORE_RUNTIME_NAME "RawrXD-CoreRuntime")

# =============================================================================
# CORE RUNTIME SOURCE INVENTORY (Minimal, Self-Contained)
# =============================================================================

set(CORE_RUNTIME_SOURCES
    # ---- Inference Engine Core ----
    src/inference/inference_engine.cpp
    src/inference/graph_executor.cpp
    src/inference/memory_pool.cpp
    src/inference/tensor_ops.cpp
    
    # ---- GGUF Loader (Headless) ----
    src/gguf/gguf_loader.cpp
    src/gguf/gguf_parser.cpp
    src/gguf/gguf_tensor.cpp
    src/gguf/vocab_resolver.cpp
    
    # ---- Embedding Engine ----
    src/embeddings/embedding_engine.cpp
    src/embeddings/vector_store.cpp
    
    # ---- Transaction Journal ----
    src/journal/transaction_log.cpp
    src/journal/checkpoint_manager.cpp
    
    # ---- Agentic Task Graph (Headless) ----
    src/agentic/task_graph.cpp
    src/agentic/task_scheduler.cpp
    src/agentic/task_executor.cpp
    
    # ---- Minimal Memory Layer ----
    src/memory/arena_allocator.cpp
    src/memory/pool_allocator.cpp
    src/memory/buffer_cache.cpp
    
    # ---- Math Kernels (AVX-512, AVX2) ----
    src/kernels/matmul_avx512.cpp
    src/kernels/matmul_avx2.cpp
    src/kernels/dequantize_q4_0.cpp
    src/kernels/dequantize_q8_0.cpp
    
    # ---- Core Utilities (No UI deps) ----
    src/core/string_util.cpp
    src/core/file_io.cpp
    src/core/time_util.cpp
    src/core/error_codes.cpp
)

# =============================================================================
# CORE RUNTIME HEADER INVENTORY (Public API)
# =============================================================================

set(CORE_RUNTIME_PUBLIC_HEADERS
    include/core_runtime/inference_engine.h
    include/core_runtime/graph_executor.h
    include/core_runtime/memory_pool.h
    include/core_runtime/tensor.h
    include/core_runtime/gguf_loader.h
    include/core_runtime/embedding_engine.h
    include/core_runtime/task_graph.h
    include/core_runtime/transaction_journal.h
)

# =============================================================================
# FORBIDDEN DEPENDENCIES (Explicitly Blocked)
# =============================================================================
# These MUST NOT be linked or included by CoreRuntime

set(CORE_RUNTIME_FORBIDDEN_LIBS
    # ---- UI Layer ----
    RawrXD-Win32IDE
    RawrXD-Codex
    RawrXD-UI
    
    # ---- Scripting ----
    quickjs
    RawrXD-QuickJS
    
    # ---- Plugins/Marketplace ----
    RawrXD-Marketplace
    RawrXD-ExtensionHost
    
    # ---- Visualization ----
    RawrXD-Renderer
    RawrXD-Visualizer
    
    # ---- Experimental ----
    RawrXD-Experimental
    RawrXD-Research
)

set(CORE_RUNTIME_FORBIDDEN_INCLUDES
    # ---- UI Headers ----
    "win32app/"
    "ui/"
    "codex/"
    "dialogs/"
    "panels/"
    
    # ---- Scripting Headers ----
    "quickjs/"
    "js_"
    
    # ---- Plugin Headers ----
    "extension_host/"
    "marketplace/"
    
    # ---- Visualization ----
    "render/"
    "viz/"
    "graphics/"
)

# =============================================================================
# CORE RUNTIME TARGET DEFINITION
# =============================================================================

add_library(${CORE_RUNTIME_NAME} STATIC ${CORE_RUNTIME_SOURCES})

# =============================================================================
# INCLUDE DIRECTORIES (Strictly Bounded)
# =============================================================================

target_include_directories(${CORE_RUNTIME_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/core_runtime
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/inference
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gguf
        ${CMAKE_CURRENT_SOURCE_DIR}/src/embeddings
        ${CMAKE_CURRENT_SOURCE_DIR}/src/journal
        ${CMAKE_CURRENT_SOURCE_DIR}/src/agentic
        ${CMAKE_CURRENT_SOURCE_DIR}/src/memory
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kernels
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

# =============================================================================
# COMPILE DEFINITIONS (Core Runtime Identity)
# =============================================================================

target_compile_definitions(${CORE_RUNTIME_NAME}
    PUBLIC
        RAWRXD_CORE_RUNTIME=1
        RAWRXD_HEADLESS_MODE=1
        RAWRXD_NO_UI=1
        RAWRXD_NO_QUICKJS=1
        RAWRXD_NO_PLUGINS=1
    PRIVATE
        RAWRXD_CORE_BUILD=1
)

# =============================================================================
# COMPILER OPTIONS (Performance-Critical)
# =============================================================================

if(MSVC)
    target_compile_options(${CORE_RUNTIME_NAME}
        PRIVATE
            /O2
            /arch:AVX2
            /fp:fast
            /GS-
            /sdl-
            /MT
            /EHsc
            /W4
            /WX-  # Don't treat warnings as errors in core (for now)
    )
endif()

# =============================================================================
# LINK LIBRARIES (Minimal External Dependencies)
# =============================================================================

target_link_libraries(${CORE_RUNTIME_NAME}
    PUBLIC
        # Only standard libraries and math
        ${CMAKE_THREAD_LIBS_INIT}
    PRIVATE
        # No external UI/scripting deps allowed
)

# =============================================================================
# DEPENDENCY VALIDATION (Build-Time Enforcement)
# =============================================================================
# This function checks that CoreRuntime doesn't accidentally link forbidden libs

function(validate_core_runtime_isolation target_name)
    get_target_property(LINKED_LIBS ${target_name} LINK_LIBRARIES)
    
    if(LINKED_LIBS)
        foreach(forbidden ${CORE_RUNTIME_FORBIDDEN_LIBS})
            if(${forbidden} IN_LIST LINKED_LIBS)
                message(FATAL_ERROR 
                    "[CoreRuntime ISOLATION VIOLATION] "
                    "Target ${target_name} illegally links forbidden library: ${forbidden}"
                )
            endif()
        endforeach()
    endif()
    
    message(STATUS "[CoreRuntime] Isolation validated for ${target_name}")
endfunction()

# Run validation at configure time
validate_core_runtime_isolation(${CORE_RUNTIME_NAME})

# =============================================================================
# SYMBOL VISIBILITY (Hide Implementation Details)
# =============================================================================

set_target_properties(${CORE_RUNTIME_NAME} PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

# =============================================================================
# CORE RUNTIME TEST TARGET
# =============================================================================
# Minimal test harness that validates CoreRuntime works without any UI deps

add_executable(RawrXD-CoreRuntime-Test
    tests/core_runtime/test_inference_loop.cpp
    tests/core_runtime/test_gguf_loader.cpp
    tests/core_runtime/test_task_graph.cpp
    tests/core_runtime/test_memory_pool.cpp
)

target_link_libraries(RawrXD-CoreRuntime-Test
    PRIVATE
        ${CORE_RUNTIME_NAME}
)

# Validate test target also has clean dependencies
validate_core_runtime_isolation(RawrXD-CoreRuntime-Test)

# =============================================================================
# CORE RUNTIME EXPORT HEADER
# =============================================================================
# Generates version info and export macros

include(GenerateExportHeader)
generate_export_header(${CORE_RUNTIME_NAME}
    BASE_NAME RAWRXD_CORE
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/core_runtime/core_export.h
)

target_include_directories(${CORE_RUNTIME_NAME}
    PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}/include/core_runtime
)

message(STATUS "[CoreRuntime] Target ${CORE_RUNTIME_NAME} configured")
message(STATUS "[CoreRuntime] Sources: ${CORE_RUNTIME_SOURCES}")
message(STATUS "[CoreRuntime] Forbidden libs: ${CORE_RUNTIME_FORBIDDEN_LIBS}")
