# CMake ExternalProject for Phase 17 Dependencies
# This module handles FAISS and tree-sitter integration

include(ExternalProject)

# Option to use HNSW fallback if FAISS build fails
option(USE_FAISS "Enable FAISS vector search" ON)
option(USE_HNSW_FALLBACK "Use HNSW as fallback" ON)

# Tree-sitter (header-only, lightweight)
ExternalProject_Add(
    treesitter
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
    GIT_TAG v0.20.8
    PREFIX ${CMAKE_BINARY_DIR}/deps/treesitter
    CONFIGURE_COMMAND ""  # Header-only, no configure
    BUILD_COMMAND ""      # Header-only, no build
    INSTALL_COMMAND ""    # Header-only, no install
    LOG_DOWNLOAD ON
)

# HNSW (header-only, always available as fallback)
ExternalProject_Add(
    hnsw
    GIT_REPOSITORY https://github.com/nmslib/hnswlib.git
    GIT_TAG v0.7.0
    PREFIX ${CMAKE_BINARY_DIR}/deps/hnsw
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
)

# FAISS (optional, with fallback)
if(USE_FAISS)
    find_package(BLAS QUIET)
    find_package(LAPACK QUIET)
    
    if(BLAS_FOUND AND LAPACK_FOUND)
        ExternalProject_Add(
            faiss
            GIT_REPOSITORY https://github.com/facebookresearch/faiss.git
            GIT_TAG v1.7.4
            PREFIX ${CMAKE_BINARY_DIR}/deps/faiss
            CMAKE_ARGS 
                -DFAISS_ENABLE_GPU=OFF
                -DFAISS_ENABLE_PYTHON=OFF
                -DBUILD_SHARED_LIBS=ON
                -DCMAKE_BUILD_TYPE=Release
            LOG_CONFIGURE ON
            LOG_BUILD ON
        )
        set(FAISS_AVAILABLE TRUE)
    else()
        message(WARNING "BLAS/LAPACK not found. Using HNSW fallback.")
        set(FAISS_AVAILABLE FALSE)
    endif()
else()
    set(FAISS_AVAILABLE FALSE)
endif()

# Create interface library for semantic search
add_library(SemanticSearch INTERFACE)
add_dependencies(SemanticSearch treesitter hnsw)

if(FAISS_AVAILABLE)
    target_compile_definitions(SemanticSearch INTERFACE USE_FAISS=1)
    target_link_libraries(SemanticSearch INTERFACE faiss)
else()
    target_compile_definitions(SemanticSearch INTERFACE USE_HNSW=1)
endif()

target_include_directories(SemanticSearch INTERFACE
    ${CMAKE_BINARY_DIR}/deps/treesitter/src/treesitter/lib/include
    ${CMAKE_BINARY_DIR}/deps/hnsw/src/hnsw
)

# Dependency smoke test
add_custom_target(deps_smoke
    COMMAND ${CMAKE_COMMAND} -E echo "Testing Phase 17 dependencies..."
    COMMAND ${CMAKE_COMMAND} -E echo "Tree-sitter: $<TARGET_EXISTS:treesitter>"
    COMMAND ${CMAKE_COMMAND} -E echo "HNSW: $<TARGET_EXISTS:hnsw>"
    DEPENDS SemanticSearch
)
