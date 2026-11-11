# Win32IDE - Main GUI Application
# Demonstrates VS-compatible executable with DLL dependencies, MASM64, WebView2

cmake_minimum_required(VERSION 3.20)

# Include shared library support
include(${CMAKE_SOURCE_DIR}/cmake/RawrXDSharedLibrary.cmake)

# =============================================================================
# Win32IDE Sources
# =============================================================================

set(WIN32IDE_SOURCES
    # Core Win32 files
    Win32IDE_Main.cpp
    Win32IDE_Window.cpp
    Win32IDE_MessageLoop.cpp
    Win32IDE_Resource.cpp
    
    # UI Components
    Win32IDE_TabManager.cpp
    Win32IDE_SyntaxHighlight.cpp
    Win32IDE_TextEngine.cpp
    Win32IDE_StatusBar.cpp
    Win32IDE_ToolBar.cpp
    Win32IDE_Menu.cpp
    
    # Editor Features
    Win32IDE_IntelliSense.cpp
    Win32IDE_CodeCompletion.cpp
    Win32IDE_Diagnostics.cpp
    Win32IDE_Refactoring.cpp
    Win32IDE_Search.cpp
    
    # Terminal
    Win32IDE_Terminal.cpp
    Win32IDE_TerminalTabs.cpp
    Win32IDE_TerminalProfiles.cpp
    Win32IDE_TerminalAnsi.cpp
    
    # Debugging
    Win32IDE_Debugger.cpp
    Win32IDE_Breakpoints.cpp
    Win32IDE_WatchWindow.cpp
    Win32IDE_CallStack.cpp
    Win32IDE_MemoryView.cpp
    Win32IDE_Disassembly.cpp
    
    # Git Integration
    Win32IDE_Git.cpp
    Win32IDE_GitDiff.cpp
    Win32IDE_GitHistory.cpp
    Win32IDE_GitBranches.cpp
    
    # Agentic AI Integration
    Win32IDE_AgenticChat.cpp
    Win32IDE_AgenticTools.cpp
    Win32IDE_AgenticOrchestrator.cpp
    
    # Inference Integration
    Win32IDE_InferencePanel.cpp
    Win32IDE_ModelManager.cpp
    Win32IDE_TokenStream.cpp
    
    # Vulkan Renderer
    Win32IDE_VulkanRenderer.cpp
    Win32IDE_VulkanSwapchain.cpp
    Win32IDE_VulkanUI.cpp
    
    # WebView2 Integration
    Win32IDE_WebView2.cpp
    Win32IDE_WebView2Bridge.cpp
    
    # Settings & Configuration
    Win32IDE_Settings.cpp
    Win32IDE_Themes.cpp
    Win32IDE_Keybindings.cpp
    
    # Extensions
    Win32IDE_ExtensionHost.cpp
    Win32IDE_ExtensionAPI.cpp
    Win32IDE_Marketplace.cpp
    
    # Utilities
    Win32IDE_Logging.cpp
    Win32IDE_Profiler.cpp
    Win32IDE_CrashHandler.cpp
)

set(WIN32IDE_HEADERS
    Win32IDE.h
    Win32IDE_Types.h
    Win32IDE_Window.h
    Win32IDE_TabManager.h
    Win32IDE_TextEngine.h
    Win32IDE_Terminal.h
    Win32IDE_Debugger.h
    Win32IDE_Agentic.h
    Win32IDE_Inference.h
    Win32IDE_Vulkan.h
    Win32IDE_WebView2.h
    Win32IDE_Extensions.h
)

# =============================================================================
# MASM64 Assembly Sources (if enabled)
# =============================================================================

set(WIN32IDE_ASM_SOURCES "")
if(RAWRXD_ENABLE_MASM AND MSVC)
    set(WIN32IDE_ASM_SOURCES
        ${CMAKE_SOURCE_DIR}/src/asm/Win32IDE_MainLoop.asm
        ${CMAKE_SOURCE_DIR}/src/asm/Win32IDE_MessagePump.asm
        ${CMAKE_SOURCE_DIR}/src/asm/Win32IDE_HotKeys.asm
        ${CMAKE_SOURCE_DIR}/src/asm/Win32IDE_Graphics.asm
        ${CMAKE_SOURCE_DIR}/src/asm/Win32IDE_SIMD.asm
    )
    set_source_files_properties(${WIN32IDE_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)
endif()

# =============================================================================
# Resource File
# =============================================================================

set(WIN32IDE_RESOURCE ${CMAKE_SOURCE_DIR}/src/win32app/Resource.rc)
if(EXISTS ${WIN32IDE_RESOURCE})
    set_source_files_properties(${WIN32IDE_RESOURCE} PROPERTIES LANGUAGE RC)
endif()

# =============================================================================
# Create Executable
# =============================================================================

rawrxd_add_executable(RawrXD-Win32IDE
    SOURCES ${WIN32IDE_SOURCES} ${WIN32IDE_ASM_SOURCES} ${WIN32IDE_RESOURCE}
    HEADERS ${WIN32IDE_HEADERS}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/runtime
        ${CMAKE_SOURCE_DIR}/3rdparty
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
    COMPILE_DEFINITIONS
        RAWXD_WIN32IDE_BUILD
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
        _CRT_SECURE_NO_WARNINGS
        $<$<BOOL:${RAWRXD_ENABLE_VULKAN}>:RAWR_HAS_VULKAN=1>
        $<$<BOOL:${RAWRXD_ENABLE_MASM}>:RAWR_HAS_MASM=1>
    LINK_LIBRARIES
        RawrXDCore
        rawrxd_runtime
        ${CMAKE_SOURCE_DIR}/src/engine  # If engine target exists
    COMPILE_OPTIONS
        $<$<COMPILE_LANGUAGE:CXX>:/std:c++20>
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/FS>
    LINK_OPTIONS
        $<$<CONFIG:Release>:/LTCG>
    DEPENDS
        RawrXDCore
        rawrxd_runtime
)

# =============================================================================
# Target Properties
# =============================================================================

set_target_properties(RawrXD-Win32IDE PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    VS_DEBUGGER_COMMAND_ARGUMENTS ""
    DEBUG_POSTFIX "d"
    FOLDER "${RAWRXD_FOLDER_APPS}"
    VS_GLOBAL_ImportProps "${CMAKE_SOURCE_DIR}/cmake/RawrXD.Common.props;${CMAKE_SOURCE_DIR}/cmake/RawrXD.Executable.props"
    VS_GLOBAL_ProjectIsGenerated "true"
)

# Per-configuration output directories
set_target_properties(RawrXD-Win32IDE PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/MinSizeRel"
)

# MSVC Runtime: MultiThreadedDLL for EXE linking to DLLs
if(MSVC)
    set_target_properties(RawrXD-Win32IDE PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>"
    )
endif()

# =============================================================================
# WebView2 Integration
# =============================================================================

if(Microsoft_Web_WebView2_FOUND)
    target_link_libraries(RawrXD-Win32IDE PRIVATE Microsoft.Web.WebView2::WebView2)
    target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWR_HAS_WEBVIEW2=1)
else()
    target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWR_HAS_WEBVIEW2=0)
endif()

# =============================================================================
# Vulkan Integration
# =============================================================================

if(RAWRXD_ENABLE_VULKAN AND Vulkan_FOUND)
    target_include_directories(RawrXD-Win32IDE PRIVATE ${Vulkan_INCLUDE_DIRS})
    target_link_libraries(RawrXD-Win32IDE PRIVATE Vulkan::Vulkan)
    target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWR_HAS_VULKAN=1)
else()
    target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWR_HAS_VULKAN=0)
endif()

# =============================================================================
# Windows System Libraries
# =============================================================================

if(WIN32)
    target_link_libraries(RawrXD-Win32IDE PRIVATE
        kernel32
        user32
        gdi32
        winspool
        comdlg32
        advapi32
        shell32
        ole32
        oleaut32
        uuid
        odbc32
        odbccp32
        shlwapi
        comctl32
        version
        ws2_32
        dwmapi
        uxtheme
        d3d11
        dxgi
        d2d1
        dwrite
        windowscodecs
    )
endif()

# =============================================================================
# MASM64 Include Paths
# =============================================================================

if(RAWRXD_ENABLE_MASM AND MSVC)
    target_include_directories(RawrXD-Win32IDE PRIVATE
        ${CMAKE_SOURCE_DIR}/src/asm
        ${CMAKE_SOURCE_DIR}/include
    )
endif()

# =============================================================================
# Install
# =============================================================================

if(RAWRXD_INSTALL)
    install(TARGETS RawrXD-Win32IDE
        RUNTIME DESTINATION bin
        BUNDLE DESTINATION .
    )
    
    install(FILES ${WIN32IDE_HEADERS}
        DESTINATION include/rawrxd/win32ide
    )
endif()

# =============================================================================
# Tests for Win32IDE
# =============================================================================

if(RAWRXD_BUILD_TESTS)
    add_executable(Win32IDE_Tests
        tests/Win32IDE_UnitTests.cpp
        tests/Win32IDE_IntegrationTests.cpp
    )
    target_link_libraries(Win32IDE_Tests PRIVATE RawrXD-Win32IDE)
    target_compile_features(Win32IDE_Tests PRIVATE cxx_std_20)
    
    add_test(NAME Win32IDE_UnitTests COMMAND Win32IDE_Tests --unit)
    add_test(NAME Win32IDE_IntegrationTests COMMAND Win32IDE_Tests --integration)
endif()

message(STATUS "[Win32IDE] VS-compatible executable configured")
message(STATUS "  Sources: ${WIN32IDE_SOURCES}")
message(STATUS "  ASM: ${WIN32IDE_ASM_SOURCES}")
message(STATUS "  Resource: ${WIN32IDE_RESOURCE}")
message(STATUS "  DLL Deps: RawrXDCore, rawrxd_runtime")
message(STATUS "  WebView2: ${Microsoft_Web_WebView2_FOUND}")
message(STATUS "  Vulkan: ${Vulkan_FOUND}")