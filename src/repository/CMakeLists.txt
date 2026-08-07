# ============================================================================
# Repository Intelligence Module — CMake Configuration
# Deep code understanding and semantic search for RawrXD
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# Repository Intelligence Library
add_library(rawrxd_repository STATIC
    RepositoryIntelligence.cpp
    RepositoryIntelligence.hpp
    ../repo/FileIndex.cpp
    ../repo/SymbolTable.cpp
    ../repo/ASTCache.cpp
    ../repo/TypeDatabase.cpp
    ../repo/CallGraph.cpp
    ../repo/IncludeGraph.cpp
    ../repo/SearchIndex.cpp
    ../repo/EmbeddingIndex.cpp
)

target_include_directories(rawrxd_repository PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../repo
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(rawrxd_repository PUBLIC
)

# Installation
install(TARGETS rawrxd_repository
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
