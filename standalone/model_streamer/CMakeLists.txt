cmake_minimum_required(VERSION 3.20)
project(RawrXD-ModelStreamer VERSION 1.0.0 LANGUAGES CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/gguf_types.cpp
    src/gguf_loader.cpp
)

# Header files
set(HEADERS
    include/gguf_types.h
    include/gguf_loader.h
)

# Static library
add_library(model_streamer STATIC ${SOURCES} ${HEADERS})

target_include_directories(model_streamer PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(model_streamer PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(model_streamer PRIVATE kernel32)
endif()

# Test executable
add_executable(test_model_loader tests/test_model_loader.cpp)
target_link_libraries(test_model_loader PRIVATE model_streamer)

# Streaming test
add_executable(test_streaming tests/test_streaming.cpp)
target_link_libraries(test_streaming PRIVATE model_streamer)

# Enable testing
enable_testing()
add_test(NAME model_loader_test COMMAND test_model_loader)
add_test(NAME streaming_test COMMAND test_streaming)

# Installation
install(TARGETS model_streamer
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${HEADERS}
    DESTINATION include
)

# Summary
message(STATUS "========================================")
message(STATUS "RawrXD Model Streamer Configuration")
message(STATUS "========================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Sources: ${SOURCES}")
message(STATUS "========================================")