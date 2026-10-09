# RawrXD VS Compatibility Test Suite
# Validates: DLL loading, multi-config, debugging, project dependencies

cmake_minimum_required(VERSION 3.20)

project(RawrXD_VSCompatTests VERSION 1.0.0 LANGUAGES CXX)

include(${CMAKE_SOURCE_DIR}/cmake/RawrXDSharedLibrary.cmake)

# Find Threads for multi-threaded tests
find_package(Threads REQUIRED)

# Helper function to get runtime library flags based on BUILD_SHARED_LIBS
function(get_runtime_flags VAR_DEBUG VAR_RELEASE VAR_RELWITHDEBINFO VAR_MINSIZEREL)
    if(BUILD_SHARED_LIBS)
        set(${VAR_DEBUG} "/MDd")
        set(${VAR_RELEASE} "/MD")
        set(${VAR_RELWITHDEBINFO} "/MD")
        set(${VAR_MINSIZEREL} "/MD")
    else()
        set(${VAR_DEBUG} "/MTd")
        set(${VAR_RELEASE} "/MT")
        set(${VAR_RELWITHDEBINFO} "/MT")
        set(${VAR_MINSIZEREL} "/MT")
    endif()
endfunction()

get_runtime_flags(RUNTIME_DEBUG RUNTIME_RELEASE RUNTIME_RELWITHDEBINFO RUNTIME_MINSIZEREL)

# Helper to add runtime flags to a target
function(add_runtime_flags TARGET)
    target_compile_options(${TARGET} PRIVATE
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Debug>>:${RUNTIME_DEBUG}>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Debug>>:${RUNTIME_DEBUG}>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:Release>>:${RUNTIME_RELEASE}>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Release>>:${RUNTIME_RELEASE}>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:RelWithDebInfo>>:${RUNTIME_RELWITHDEBINFO}>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:RelWithDebInfo>>:${RUNTIME_RELWITHDEBINFO}>
        $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CONFIG:MinSizeRel>>:${RUNTIME_MINSIZEREL}>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:MinSizeRel>>:${RUNTIME_MINSIZEREL}>
    )
endfunction()

# Include directories for RawrXDCore
set(RAWRXD_CORE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/src/core/dll")

# =============================================================================
# Test 1: Basic DLL Load/Unload
# =============================================================================

add_executable(test_dll_load_unload
    test_dll_load_unload.cpp
)
target_link_libraries(test_dll_load_unload PRIVATE RawrXDCore)
target_compile_features(test_dll_load_unload PRIVATE cxx_std_20)

set_target_properties(test_dll_load_unload PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_dll_load_unload)

add_test(NAME VS_DLL_LoadUnload_DEBUG
    COMMAND test_dll_load_unload
    CONFIGURATIONS Debug
)
add_test(NAME VS_DLL_LoadUnload_RELEASE
    COMMAND test_dll_load_unload
    CONFIGURATIONS Release
)

# =============================================================================
# Test 2: Multi-threaded DLL Access
# =============================================================================

add_executable(test_dll_multithread
    test_dll_multithread.cpp
)
target_link_libraries(test_dll_multithread PRIVATE RawrXDCore Threads::Threads)
target_compile_features(test_dll_multithread PRIVATE cxx_std_20)

set_target_properties(test_dll_multithread PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_dll_multithread)

add_test(NAME VS_DLL_Multithread_DEBUG
    COMMAND test_dll_multithread
    CONFIGURATIONS Debug
)
add_test(NAME VS_DLL_Multithread_RELEASE
    COMMAND test_dll_multithread
    CONFIGURATIONS Release
)

# =============================================================================
# Test 3: C++ API Validation
# =============================================================================

add_executable(test_cpp_api
    test_cpp_api.cpp
)
target_link_libraries(test_cpp_api PRIVATE RawrXDCore)
target_compile_features(test_cpp_api PRIVATE cxx_std_20)

set_target_properties(test_cpp_api PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_cpp_api)

add_test(NAME VS_CPP_API_DEBUG
    COMMAND test_cpp_api
    CONFIGURATIONS Debug
)
add_test(NAME VS_CPP_API_RELEASE
    COMMAND test_cpp_api
    CONFIGURATIONS Release
)

# =============================================================================
# Test 4: Inference Engine Integration
# =============================================================================

add_executable(test_inference_integration
    test_inference_integration.cpp
)
target_link_libraries(test_inference_integration PRIVATE RawrXDCore rawrxd_runtime)
target_compile_features(test_inference_integration PRIVATE cxx_std_20)

set_target_properties(test_inference_integration PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_inference_integration)

add_test(NAME VS_InferenceIntegration_DEBUG
    COMMAND test_inference_integration
    CONFIGURATIONS Debug
)
add_test(NAME VS_InferenceIntegration_RELEASE
    COMMAND test_inference_integration
    CONFIGURATIONS Release
)

# =============================================================================
# Test 5: Win32IDE Integration
# =============================================================================

add_executable(test_win32ide_integration
    test_win32ide_integration.cpp
)
target_link_libraries(test_win32ide_integration PRIVATE RawrXDCore rawrxd_runtime)
target_compile_features(test_win32ide_integration PRIVATE cxx_std_20)

set_target_properties(test_win32ide_integration PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_win32ide_integration)

add_test(NAME VS_Win32IDE_Integration_DEBUG
    COMMAND test_win32ide_integration
    CONFIGURATIONS Debug
)
add_test(NAME VS_Win32IDE_Integration_RELEASE
    COMMAND test_win32ide_integration
    CONFIGURATIONS Release
)

# =============================================================================
# Test 6: Configuration Round-trip
# =============================================================================

add_executable(test_config_roundtrip
    test_config_roundtrip.cpp
)
target_link_libraries(test_config_roundtrip PRIVATE RawrXDCore)
target_compile_features(test_config_roundtrip PRIVATE cxx_std_20)

set_target_properties(test_config_roundtrip PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_config_roundtrip)

add_test(NAME VS_Config_Roundtrip_DEBUG
    COMMAND test_config_roundtrip
    CONFIGURATIONS Debug
)
add_test(NAME VS_Config_Roundtrip_RELEASE
    COMMAND test_config_roundtrip
    CONFIGURATIONS Release
)

# =============================================================================
# Test 7: Memory Stress Test
# =============================================================================

add_executable(test_memory_stress
    test_memory_stress.cpp
)
target_link_libraries(test_memory_stress PRIVATE RawrXDCore)
target_compile_features(test_memory_stress PRIVATE cxx_std_20)

set_target_properties(test_memory_stress PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_memory_stress)

add_test(NAME VS_Memory_Stress_DEBUG
    COMMAND test_memory_stress
    CONFIGURATIONS Debug
)
add_test(NAME VS_Memory_Stress_RELEASE
    COMMAND test_memory_stress
    CONFIGURATIONS Release
)

# =============================================================================
# Test 8: Symbol Export Verification
# =============================================================================

add_executable(test_symbol_exports
    test_symbol_exports.cpp
)
target_link_libraries(test_symbol_exports PRIVATE RawrXDCore)
target_compile_features(test_symbol_exports PRIVATE cxx_std_20)

set_target_properties(test_symbol_exports PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_symbol_exports)

add_test(NAME VS_Symbol_Exports_DEBUG
    COMMAND test_symbol_exports
    CONFIGURATIONS Debug
)
add_test(NAME VS_Symbol_Exports_RELEASE
    COMMAND test_symbol_exports
    CONFIGURATIONS Release
)

# =============================================================================
# Test 9: Cross-config Compatibility
# =============================================================================

# This test verifies that a Debug executable can load a Release DLL and vice versa
# (should work with proper /MD /MDd runtime matching)
add_executable(test_cross_config
    test_cross_config.cpp
)
target_link_libraries(test_cross_config PRIVATE RawrXDCore)
target_compile_features(test_cross_config PRIVATE cxx_std_20)

set_target_properties(test_cross_config PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_cross_config)

add_test(NAME VS_Cross_Config_DEBUG
    COMMAND test_cross_config
    CONFIGURATIONS Debug
)
add_test(NAME VS_Cross_Config_RELEASE
    COMMAND test_cross_config
    CONFIGURATIONS Release
)

# =============================================================================
# Test 10: Debug Information Validation
# =============================================================================

add_executable(test_debug_info
    test_debug_info.cpp
)
target_link_libraries(test_debug_info PRIVATE RawrXDCore)
target_compile_features(test_debug_info PRIVATE cxx_std_20)

set_target_properties(test_debug_info PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_TESTS}"
)

add_runtime_flags(test_debug_info)

add_test(NAME VS_Debug_Info_DEBUG
    COMMAND test_debug_info
    CONFIGURATIONS Debug
)
add_test(NAME VS_Debug_Info_RELEASE
    COMMAND test_debug_info
    CONFIGURATIONS Release
)

# =============================================================================
# Enable testing
# =============================================================================

enable_testing()
include(CTest)

message(STATUS "[VS Compat Tests] 10 test suites configured for Debug/Release")
message(STATUS "  Run with: ctest -C Debug -VV")
message(STATUS "  Run with: ctest -C Release -VV")