# ============================================================================
# rawrxd_production_hardening - production-hardening runtime
# ============================================================================
# A dependency-free static library (Windows stdlib + CNG only) that provides
# the operational layer a production deployment of RawrXD needs:
#
#   configuration    typed, validated, env/CLI-overridable settings
#   observability    structured JSON logs with rotation, metrics, tracing,
#                    health components
#   reliability      circuit breakers, retry with jitter, bulkheads,
#                    fallback chains, feature gates
#   security         AES-256-GCM at rest (bcrypt), input validation,
#                    append-only hash-chained audit log, secret redaction
#   readiness        ordered startup gates that refuse to serve when unhealthy
#
# Every consumer links this and calls ProductionRuntime::init() once. Nothing
# in here depends on Qt, ggml, or any subsystem outside src/production, so it
# can be built and tested on its own.
#
# This file is deliberately self-sufficient: it works both as a subdirectory of
# the root project and as a standalone CMake tree, because the drop packaging
# verifies it in isolation before anything else claims to be ready.
# ============================================================================

# Declared before any target so the module can be configured on its own. The
# root project supplies the same minimum, which is why this was not previously
# required.
cmake_minimum_required(VERSION 3.24)

# Building standalone is supported, so guard the include path that normally
# comes from the parent scope. In-tree use keeps the root's include/ either
# way, so the fallback only fires when this directory is the top of the tree.
if(NOT DEFINED CMAKE_SOURCE_DIR OR CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(RAWRXD_PRODUCTION_STANDALONE ON)
endif()

# nlohmann/json is vendored at include/ in the repository. When this directory
# is built as a subdirectory the root tree provides it; when built standalone
# (which the drop packaging does, to verify the module in isolation) it is
# found in one of the layouts a drop can use. Discovery happens here, but the
# result is only applied once the target exists, because a target_* command
# before add_library is a configure error.
set(RAWRXD_JSON_INCLUDE_DIR)
foreach(_candidate
    "${CMAKE_SOURCE_DIR}/include"                    # in-tree: root project
    "${CMAKE_CURRENT_SOURCE_DIR}/../../include"      # repo (or drop) root from src/production
    "${CMAKE_CURRENT_SOURCE_DIR}/include")           # fully self-contained module
    if(EXISTS "${_candidate}/nlohmann/json.hpp")
        set(RAWRXD_JSON_INCLUDE_DIR "${_candidate}")
        break()
    endif()
endforeach()

# Pin the CRT explicitly instead of relying on the parent scope. This library
# is linked into an executable that also links ggml and the IDE sources, and a
# /MT object meeting an /MD object is an LNK2038 link error that compiles
# cleanly and only surfaces when the executable is linked.
set(RAWRXD_PRODUCTION_RUNTIME_LIB
    "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

add_library(rawrxd_production_hardening STATIC
    SovereignProductionConfig.cpp
    SovereignObservability.cpp
    SovereignReliabilityFaultTolerance.cpp
    SovereignSecurityHardening.cpp
    ProductionRuntime.cpp
)
set_property(TARGET rawrxd_production_hardening
             PROPERTY MSVC_RUNTIME_LIBRARY ${RAWRXD_PRODUCTION_RUNTIME_LIB})

target_include_directories(rawrxd_production_hardening PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
if(RAWRXD_JSON_INCLUDE_DIR)
    target_include_directories(rawrxd_production_hardening PUBLIC
        ${RAWRXD_JSON_INCLUDE_DIR}
    )
elseif(RAWRXD_PRODUCTION_STANDALONE)
    # Standalone with no vendored header anywhere means the module cannot be
    # built as shipped. Fail now, not on the first #include in a .cpp file.
    message(FATAL_ERROR
        "rawrxd_production_hardening needs nlohmann/json.hpp but found no vendored "
        "copy in any of the expected locations. In-tree builds use <root>/include; "
        "a standalone drop must ship include/nlohmann alongside src/production.")
endif()

target_compile_definitions(rawrxd_production_hardening PUBLIC
    NOMINMAX
    _WIN32_WINNT=0x0A00
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    # /W4 is intentional: this module is the baseline for quality gates, so a
    # warning here is treated as a defect in review, not noise to suppress.
    target_compile_options(rawrxd_production_hardening PRIVATE
        /EHsc /std:c++20 /W4 /permissive-
        /wd4100  # unreferenced formal parameter: interfaces keep parameters
                 # for signature compatibility
    )
    target_link_libraries(rawrxd_production_hardening PUBLIC
        bcrypt
        dbghelp
    )
else()
    target_compile_options(rawrxd_production_hardening PRIVATE
        -std=c++20 -Wall -Wextra -Wno-unused-parameter
    )
endif()

# ----------------------------------------------------------------------------
# Verification target: behavioural tests for the hardening primitives.
# These run as part of the normal build/CI path and fail loudly.
# ----------------------------------------------------------------------------
add_executable(rawrxd_production_tests
    tests/production_hardening_tests.cpp
)
set_property(TARGET rawrxd_production_tests
             PROPERTY MSVC_RUNTIME_LIBRARY ${RAWRXD_PRODUCTION_RUNTIME_LIB})
target_link_libraries(rawrxd_production_tests PRIVATE
    rawrxd_production_hardening
)
target_include_directories(rawrxd_production_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
if(RAWRXD_JSON_INCLUDE_DIR)
    target_include_directories(rawrxd_production_tests PRIVATE
        ${RAWRXD_JSON_INCLUDE_DIR}
    )
endif()
if(MSVC)
    target_compile_options(rawrxd_production_tests PRIVATE /EHsc /std:c++20 /W4)
endif()

add_test(NAME rawrxd_production_hardening
         COMMAND rawrxd_production_tests
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "rawrxd_production_hardening: production hardening runtime enabled")

# ----------------------------------------------------------------------------
# Operational probe binary: answers liveness/readiness without a GUI or a
# window manager. Built from the same library the IDE links, so a verified
# probe path is verified once and used everywhere.
# ----------------------------------------------------------------------------
add_executable(rawrxd_health_probe
    tools/health_probe.cpp
)
set_property(TARGET rawrxd_health_probe
             PROPERTY MSVC_RUNTIME_LIBRARY ${RAWRXD_PRODUCTION_RUNTIME_LIB})
target_link_libraries(rawrxd_health_probe PRIVATE
    rawrxd_production_hardening
)
target_include_directories(rawrxd_health_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
if(RAWRXD_JSON_INCLUDE_DIR)
    target_include_directories(rawrxd_health_probe PRIVATE
        ${RAWRXD_JSON_INCLUDE_DIR}
    )
endif()
if(MSVC)
    target_compile_options(rawrxd_health_probe PRIVATE /EHsc /std:c++20 /W4)
endif()
set_target_properties(rawrxd_health_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
