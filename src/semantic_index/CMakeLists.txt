# Semantic Index Module - CMake Configuration
# Phase 17C: FAISS/HNSW Vector Search Integration

cmake_minimum_required(VERSION 3.20)

# Module name
set(SEMANTIC_INDEX_MODULE semantic_index)

# Source files
set(SEMANTIC_INDEX_SOURCES
    SemanticCodeIndex.cpp
)

# Header files
set(SEMANTIC_INDEX_HEADERS
    SemanticCodeIndex.h
)

# ---------------------------------------------------------------------------
# Phase 17C: Vector Search Dependency Injection
# ---------------------------------------------------------------------------

# 1. Look for pre-installed FAISS (Optional - production builds)
# FAISS requires BLAS/LAPACK which may not be available on all dev machines
find_package(faiss CONFIG QUIET)

if(faiss_FOUND)
    message(STATUS "[Phase 17C] Found system FAISS. Enabling IVFPQ backend.")
    set(RAWR_USE_FAISS ON)
    set(SEMANTIC_INDEX_BACKEND_LIBS faiss::faiss)
else()
    # 2. HNSW fallback - header-only, no dependencies
    message(STATUS "[Phase 17C] FAISS not found. Using HNSW (header-only) backend.")
    set(RAWR_USE_FAISS OFF)
    
    # Fetch HNSW header-only library
    include(FetchContent)
    FetchContent_Declare(
        hnsw
        GIT_REPOSITORY https://github.com/nmslib/hnswlib.git
        GIT_TAG v0.8.0
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(hnsw)
    
    set(SEMANTIC_INDEX_BACKEND_LIBS "")
endif()

# 3. OpenMP for FAISS parallelization (required for IVFPQ)
find_package(OpenMP QUIET)
if(OpenMP_CXX_FOUND)
    message(STATUS "[Phase 17C] OpenMP found - enabling parallel IVFPQ search")
    set(RAWR_HAS_OPENMP ON)
else()
    message(WARNING "[Phase 17C] OpenMP not found - IVFPQ will be single-threaded")
    set(RAWR_HAS_OPENMP OFF)
endif()

# ---------------------------------------------------------------------------
# Phase 17C.3: ONNX Runtime Integration for Code Embeddings
# ---------------------------------------------------------------------------
# ONNX Runtime provides the inference engine for CodeBERT/MiniLM models
# We support both system-installed and local/staged ONNX Runtime

set(RAWR_ONNXRUNTIME_ROOT "${CMAKE_SOURCE_DIR}/3rdparty/onnxruntime" CACHE PATH "ONNX Runtime root directory")

# Try to find ONNX Runtime
set(RAWR_HAS_ONNXRUNTIME OFF)

# Check for system-installed ONNX Runtime
find_package(onnxruntime CONFIG QUIET)
if(onnxruntime_FOUND)
    message(STATUS "[Phase 17C.3] Found system ONNX Runtime")
    set(RAWR_HAS_ONNXRUNTIME ON)
    set(ONNXRUNTIME_LIBS onnxruntime::onnxruntime)
else()
    # Check for local/staged ONNX Runtime
    if(EXISTS "${RAWR_ONNXRUNTIME_ROOT}/include/onnxruntime_cxx_api.h")
        message(STATUS "[Phase 17C.3] Found local ONNX Runtime at ${RAWR_ONNXRUNTIME_ROOT}")
        set(RAWR_HAS_ONNXRUNTIME ON)
        set(ONNXRUNTIME_INCLUDE_DIR "${RAWR_ONNXRUNTIME_ROOT}/include")
        
        # Determine library path based on platform
        if(WIN32)
            if(EXISTS "${RAWR_ONNXRUNTIME_ROOT}/lib/onnxruntime.lib")
                set(ONNXRUNTIME_LIB "${RAWR_ONNXRUNTIME_ROOT}/lib/onnxruntime.lib")
            elseif(EXISTS "${RAWR_ONNXRUNTIME_ROOT}/lib/onnxruntime.dll")
                set(ONNXRUNTIME_LIB "${RAWR_ONNXRUNTIME_ROOT}/lib/onnxruntime.lib")
            endif()
        else()
            if(EXISTS "${RAWR_ONNXRUNTIME_ROOT}/lib/libonnxruntime.so")
                set(ONNXRUNTIME_LIB "${RAWR_ONNXRUNTIME_ROOT}/lib/libonnxruntime.so")
            elseif(EXISTS "${RAWR_ONNXRUNTIME_ROOT}/lib/libonnxruntime.dylib")
                set(ONNXRUNTIME_LIB "${RAWR_ONNXRUNTIME_ROOT}/lib/libonnxruntime.dylib")
            endif()
        endif()
        
        if(NOT EXISTS "${ONNXRUNTIME_LIB}")
            message(WARNING "[Phase 17C.3] ONNX Runtime headers found but library missing - embedding pipeline disabled")
            set(RAWR_HAS_ONNXRUNTIME OFF)
        endif()
    else()
        message(STATUS "[Phase 17C.3] ONNX Runtime not found - using stub embedder (deterministic hashing)")
    endif()
endif()

# Update source files based on ONNX availability
if(RAWR_HAS_ONNXRUNTIME)
    list(APPEND SEMANTIC_INDEX_SOURCES CodeEmbedder.cpp)
    list(APPEND SEMANTIC_INDEX_HEADERS CodeEmbedder.h)
endif()

# Create the library
add_library(${SEMANTIC_INDEX_MODULE} STATIC
    ${SEMANTIC_INDEX_SOURCES}
    ${SEMANTIC_INDEX_HEADERS}
)

# Define backend macros for conditional compilation
if(RAWR_USE_FAISS)
    target_compile_definitions(${SEMANTIC_INDEX_MODULE}
        PRIVATE 
            RAWR_HAS_FAISS=1
            USE_FAISS_BACKEND
    )
    if(RAWR_HAS_OPENMP)
        target_compile_definitions(${SEMANTIC_INDEX_MODULE}
            PRIVATE RAWR_HAS_OPENMP=1
        )
    endif()
else()
    target_compile_definitions(${SEMANTIC_INDEX_MODULE}
        PRIVATE USE_HNSW_BACKEND
    )
endif()

# Include directories
target_include_directories(${SEMANTIC_INDEX_MODULE}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        $<$<NOT:$<BOOL:${RAWR_USE_FAISS}>>:${hnsw_SOURCE_DIR}>
        $<$<BOOL:${RAWR_HAS_ONNXRUNTIME}>:${ONNXRUNTIME_INCLUDE_DIR}>
)

# Link libraries
target_link_libraries(${SEMANTIC_INDEX_MODULE}
    PUBLIC
        ${SEMANTIC_INDEX_BACKEND_LIBS}
)

# ONNX Runtime linkage
if(RAWR_HAS_ONNXRUNTIME)
    if(TARGET onnxruntime::onnxruntime)
        target_link_libraries(${SEMANTIC_INDEX_MODULE} PRIVATE onnxruntime::onnxruntime)
    else()
        target_link_libraries(${SEMANTIC_INDEX_MODULE} PRIVATE ${ONNXRUNTIME_LIB})
    endif()
    target_compile_definitions(${SEMANTIC_INDEX_MODULE} PRIVATE RAWR_HAS_ONNXRUNTIME=1)
endif()

# OpenMP linkage
if(RAWR_HAS_OPENMP AND OpenMP_CXX_FOUND)
    target_link_libraries(${SEMANTIC_INDEX_MODULE}
        PUBLIC
            OpenMP::OpenMP_CXX
    )
endif()

# Compiler options for performance
if(MSVC)
    target_compile_options(${SEMANTIC_INDEX_MODULE}
        PRIVATE
            /O2
            /arch:AVX2
            /fp:fast
    )
else()
    target_compile_options(${SEMANTIC_INDEX_MODULE}
        PRIVATE
            -O3
            -march=native
            -ffast-math
    )
endif()

# Smoke test executable
add_executable(semantic_index_smoke_test
    semantic_index_smoke_test.cpp
)

target_link_libraries(semantic_index_smoke_test
    PRIVATE
        ${SEMANTIC_INDEX_MODULE}
)

# Installation
install(TARGETS ${SEMANTIC_INDEX_MODULE}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${SEMANTIC_INDEX_HEADERS}
    DESTINATION include/semantic_index
)

# ---------------------------------------------------------------------------
# Phase 17C: Export configuration to parent scope
# ---------------------------------------------------------------------------
set(RAWR_SEMANTIC_INDEX_FAISS_ENABLED ${RAWR_USE_FAISS} CACHE BOOL "FAISS enabled for semantic index" FORCE)
set(RAWR_SEMANTIC_INDEX_OPENMP_ENABLED ${RAWR_HAS_OPENMP} CACHE BOOL "OpenMP enabled for semantic index" FORCE)
set(RAWR_SEMANTIC_INDEX_ONNX_ENABLED ${RAWR_HAS_ONNXRUNTIME} CACHE BOOL "ONNX Runtime enabled for semantic index" FORCE)

# Export to parent scope for main CMakeLists.txt
set(RAWR_SEMANTIC_INDEX_FAISS_ENABLED ${RAWR_USE_FAISS} PARENT_SCOPE)
set(RAWR_SEMANTIC_INDEX_OPENMP_ENABLED ${RAWR_HAS_OPENMP} PARENT_SCOPE)
set(RAWR_SEMANTIC_INDEX_ONNX_ENABLED ${RAWR_HAS_ONNXRUNTIME} PARENT_SCOPE)

# ---------------------------------------------------------------------------
# Phase 17C: Configuration Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "[Phase 17C] Semantic Index Configuration Summary:")
message(STATUS "  Backend:          $<IF:${RAWR_USE_FAISS},FAISS IVFPQ,HNSW>")
message(STATUS "  Vector Dimension: 384 (MiniLM-compatible)")
message(STATUS "  OpenMP:           $<IF:${RAWR_HAS_OPENMP},Enabled,Disabled>")
message(STATUS "  ONNX Runtime:     $<IF:${RAWR_HAS_ONNXRUNTIME},Enabled (CodeBERT),Disabled (stub embedder)>")
message(STATUS "  Memory Budget:    278MB available / ~140MB estimated")
message(STATUS "  Target:           ${SEMANTIC_INDEX_MODULE}")
message(STATUS "")