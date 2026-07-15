# Completion Module - CMake Configuration
# Phase 17C: CompletionRouter for hybrid Trie + Semantic search
# Phase 18B: AdaptiveFusionEngine for self-tuning weights

cmake_minimum_required(VERSION 3.20)

set(COMPLETION_MODULE completion)

# Source files
set(COMPLETION_SOURCES
    completion_router.cpp
    AdaptiveFusionEngine.cpp
    FeedbackListener.cpp
)

set(COMPLETION_HEADERS
    completion_router.h
    AdaptiveFusionEngine.h
    FeedbackListener.h
)

# Create the library
add_library(${COMPLETION_MODULE} STATIC
    ${COMPLETION_SOURCES}
    ${COMPLETION_HEADERS}
)

# Include directories
target_include_directories(${COMPLETION_MODULE}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/semantic_index
)

# Link dependencies
target_link_libraries(${COMPLETION_MODULE}
    PUBLIC
        semantic_index  # From src/semantic_index/
)

# Compiler options
if(MSVC)
    target_compile_options(${COMPLETION_MODULE}
        PRIVATE
            /O2
            /W3
            /EHsc
    )
else()
    target_compile_options(${COMPLETION_MODULE}
        PRIVATE
            -O3
            -Wall
    )
endif()

# Installation
install(TARGETS ${COMPLETION_MODULE}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${COMPLETION_HEADERS}
    DESTINATION include/completion
)
