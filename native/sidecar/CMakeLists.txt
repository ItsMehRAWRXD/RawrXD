# RawrXD Native Sidecar CMake Configuration
# C++23 / Win32 / Zero Node.js
# King style build system

cmake_minimum_required(VERSION 3.25)
project(RawrXD_Sidecar 
    VERSION 1.0.0
    DESCRIPTION "RawrXD Native Agent Sidecar - C++23"
    LANGUAGES CXX
)

# C++23 Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Source files
set(SIDECAR_SOURCES
    src/sidecar_main.cpp
    src/hnsw_index.cpp
    src/sovereign_context.cpp
    src/speculative_coding.cpp
)

# Header files (for IDE support)
set(SIDECAR_HEADERS
    include/sidecar_protocol.hpp
    include/sovereign_context.hpp
    include/speculative_coding.hpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SIDECAR_SOURCES} ${SIDECAR_HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Windows-specific settings
if(WIN32)
    # Windows libraries for named pipes and threading
    target_link_libraries(${PROJECT_NAME} PRIVATE
        kernel32      # Windows API
        ws2_32        # Winsock (if needed)
    )
    
    # Windows-specific defines
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        _WIN32_WINNT=0x0A00     # Windows 10
        WIN32_LEAN_AND_MEAN     # Exclude rarely-used stuff
        NOMINMAX                # Don't define min/max macros
    )
    
    # Console subsystem
    set_target_properties(${PROJECT_NAME} PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif()

# Compiler-specific optimizations
if(MSVC)
    # Visual Studio optimizations
    target_compile_options(${PROJECT_NAME} PRIVATE
        /O2                 # Optimize for speed
        /Ob2                # Inline function expansion
        /Oi                 # Enable intrinsic functions
        /Ot                 # Favor fast code
        /GL                 # Whole program optimization
        /W4                 # Warning level 4
        /WX-                # Don't treat warnings as errors
        /permissive-        # Strict conformance
        /Zc:__cplusplus     # Correct __cplusplus macro
        /EHsc               # Exception handling
        /MP                 # Multi-processor compilation
    )
    
    # Link-time optimization
    set_target_properties(${PROJECT_NAME} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION TRUE
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # GCC/Clang optimizations
    target_compile_options(${PROJECT_NAME} PRIVATE
        -O3                 # Optimize for speed
        -march=native       # Optimize for host CPU
        -mtune=native       # Tune for host CPU
        -flto               # Link-time optimization
        -Wall               # All warnings
        -Wextra             # Extra warnings
        -Wpedantic          # Pedantic warnings
        -pthread            # POSIX threads
    )
    
    target_link_options(${PROJECT_NAME} PRIVATE
        -flto               # Link-time optimization
        -pthread            # POSIX threads
    )
endif()

# Find nlohmann/json (JSON library)
# Try to find installed version first
find_package(nlohmann_json 3.11 QUIET)

if(NOT nlohmann_json_FOUND)
    # Fetch from GitHub if not found
    include(FetchContent)
    FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(json)
endif()

# Link JSON library
target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json
)

# Precompiled headers for faster builds
target_precompile_headers(${PROJECT_NAME} PRIVATE
    <vector>
    <string>
    <map>
    <unordered_map>
    <memory>
    <functional>
    <chrono>
    <thread>
    <mutex>
    <atomic>
    <future>
    <json/json.hpp>
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${SIDECAR_HEADERS}
    DESTINATION include/rawrxd
)

# Print configuration summary
message(STATUS "")
message(STATUS "========================================")
message(STATUS "  RawrXD Native Sidecar Configuration")
message(STATUS "========================================")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "C++ Standard:   ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:       ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Output Dir:     ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "JSON Library:   ${nlohmann_json_FOUND ? "Found" : "Fetching"}")
message(STATUS "========================================")
message(STATUS "")

# Testing (optional)
enable_testing()

# Add a simple test to verify the binary runs
add_test(NAME SidecarRuns
    COMMAND ${PROJECT_NAME} --version
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# Custom target for quick build
add_custom_target(sidecar-quick
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${PROJECT_NAME} --parallel
    COMMENT "Quick build of RawrXD Sidecar"
)

# Custom target for clean rebuild
add_custom_target(sidecar-rebuild
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --clean-first --target ${PROJECT_NAME} --parallel
    COMMENT "Clean rebuild of RawrXD Sidecar"
)
