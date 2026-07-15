# Policy Layer CMakeLists.txt
# Layer 3: Observes only - recommendations, never controls

cmake_minimum_required(VERSION 3.20)
project(RawrXD-Policy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(POLICY_SOURCES
    policy.cpp
)

set(POLICY_HEADERS
    policy.h
)

# Create static library
add_library(RawrXD-Policy STATIC ${POLICY_SOURCES} ${POLICY_HEADERS})

# Set include directories
target_include_directories(RawrXD-Policy
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Compiler options
if(MSVC)
    target_compile_options(RawrXD-Policy PRIVATE
        /W4
        /WX-
        /EHsc
        /MP
    )
else()
    target_compile_options(RawrXD-Policy PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# Install headers
install(FILES ${POLICY_HEADERS}
    DESTINATION include/rawrxd/policy
)

install(TARGETS RawrXD-Policy
    DESTINATION lib
)
