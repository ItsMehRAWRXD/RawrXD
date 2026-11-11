# ============================================================================
# CMake Integration for RawrXD IDE AWS Bedrock Native Client
# ============================================================================
#
# Add to the main CMakeLists.txt:
#   include(src/ide/cmake_aws_bridge.cmake)
#
# Or add the library target to your existing build:
#   target_link_libraries(RawrXD-Win32IDE PRIVATE SovereignAwsBridge)
# ============================================================================

# AWS Bedrock Native Client library
if(ENABLE_AWS_BEDROCK OR RAWRXD_BUILD_WIN32IDE)
    set(AWS_BRIDGE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/AwsSigV4Signer.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/AwsBedrockClient.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/SovereignAwsBridge.cpp
    )
    
    set(AWS_BRIDGE_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/AwsSigV4Signer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/AwsBedrockClient.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide/SovereignAwsBridge.h
    )
    
    add_library(SovereignAwsBridge STATIC
        ${AWS_BRIDGE_SOURCES}
        ${AWS_BRIDGE_HEADERS}
    )
    
    target_include_directories(SovereignAwsBridge PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ide
    )
    
    target_compile_definitions(SovereignAwsBridge PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        _WINSOCK_DEPRECATED_NO_WARNINGS
    )
    
    target_compile_features(SovereignAwsBridge PRIVATE cxx_std_17)
    
    if(WIN32)
        target_link_libraries(SovereignAwsBridge PRIVATE
            ws2_32
            secur32
            advapi32
            crypt32
        )
    endif()
    
    set_target_properties(SovereignAwsBridge PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
    
    message(STATUS "  ✓ Added SovereignAwsBridge library (AWS Bedrock native client)")
    
    # Optionally link into the main IDE target
    if(TARGET RawrXD-Win32IDE)
        target_link_libraries(RawrXD-Win32IDE PRIVATE SovereignAwsBridge)
        target_include_directories(RawrXD-Win32IDE PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/ide
        )
        message(STATUS "  ✓ Linked SovereignAwsBridge into RawrXD-Win32IDE")
    endif()
endif()

# ============================================================================
# Custom target for building just the AWS bridge
# ============================================================================
if(ENABLE_AWS_BEDROCK)
    add_custom_target(build_aws_bridge
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target SovereignAwsBridge
        COMMENT "Building AWS Bedrock native client library"
    )
endif()
