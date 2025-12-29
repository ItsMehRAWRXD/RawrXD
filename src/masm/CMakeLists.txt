# CMakeLists.txt for Pure MASM x64 Hotpatch System
# ZERO C/C++ DEPENDENCIES - Pure Assembly Only
# Links directly to kernel32.lib via ml64/link

cmake_minimum_required(VERSION 3.20)

# Project is ASM_MASM ONLY - no C, no CXX
project(RawrXD_MASM_Hotpatch ASM_MASM)

# Enable MASM for x64
enable_language(ASM_MASM)

# Set compiler flags for MASM
# /I flag adds include directory path so ml64.exe can find .inc files
set(CMAKE_ASM_MASM_FLAGS "/nologo /Zi /c /Cp /W3 /I\"${CMAKE_CURRENT_SOURCE_DIR}/final-ide\"")

# Platform check - Windows only
if(NOT WIN32)
    message(FATAL_ERROR "MASM x64 hotpatch system requires Windows with MSVC toolchain")
endif()

# Verify x64 architecture
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "64-bit build required for MASM x64 implementation")
endif()

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ==== MASM Runtime Foundation Library ====
set(MASM_RUNTIME_SOURCES
    asm_memory.asm
    asm_sync.asm
    asm_string.asm
    asm_events.asm
    asm_log.asm
)

# ==== Qt6 Foundation Layer (NEW) ====
# Pure MASM implementation of Qt6 foundation abstractions
# Provides: object model (VMT), memory pools, event queue, signal/slot binding
set(MASM_QT6_FOUNDATION_SOURCES
    final-ide/qt6_foundation.asm
    final-ide/qt6_main_window.asm
    final-ide/qt6_text_editor.asm
    final-ide/qt6_syntax_highlighter.asm
    final-ide/qt6_statusbar.asm
)

option(ENABLE_MASM_EXPERIMENTAL_OPS "Build experimental MASM tensor/logging modules" OFF)
if(ENABLE_MASM_EXPERIMENTAL_OPS)
    list(APPEND MASM_RUNTIME_SOURCES
        asm_logging_prod.asm
        asm_tensor_ops.asm
    )
endif()

# Check qt6_foundation.asm exists
foreach(src ${MASM_QT6_FOUNDATION_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        message(WARNING "Qt6 foundation source missing: ${src}")
    else()
        message(STATUS "Qt6 foundation found: ${src}")
    endif()
endforeach()

# Create object library (no linker involved yet)
add_library(masm_runtime_obj OBJECT ${MASM_RUNTIME_SOURCES})
add_library(masm_qt6_foundation_obj OBJECT ${MASM_QT6_FOUNDATION_SOURCES})

# ==== MASM Agentic System ====

# Create static library from objects
add_library(masm_runtime STATIC $<TARGET_OBJECTS:masm_runtime_obj>)
set_target_properties(masm_runtime PROPERTIES
    OUTPUT_NAME "masm_runtime"
)

# Qt6 Foundation Library
add_library(masm_qt6_foundation STATIC $<TARGET_OBJECTS:masm_qt6_foundation_obj>)
set_target_properties(masm_qt6_foundation PROPERTIES
    OUTPUT_NAME "masm_qt6_foundation"
)

# ==== MASM Hotpatch Core Library ====
set(MASM_HOTPATCH_SOURCES
    model_memory_hotpatch.asm
    RawrXD_DualEngineStreamer.asm
    RawrXD_RuntimePatcher.asm
    RawrXD_DualEngineManager.asm
    RawrXD_AgenticPatchOrchestrator.asm
    RawrXD_MathHotpatchEntry.asm
    stub_completion_comprehensive_v2.asm
    stub_integration_bridges.asm
)

# Check which files exist and only include existing ones
foreach(src ${MASM_HOTPATCH_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        message(WARNING "MASM source file missing: ${src}")
        list(REMOVE_ITEM MASM_HOTPATCH_SOURCES ${src})
    endif()
endforeach()

add_library(masm_hotpatch_core_obj OBJECT ${MASM_HOTPATCH_SOURCES})
add_library(masm_hotpatch_core STATIC $<TARGET_OBJECTS:masm_hotpatch_core_obj>)
set_target_properties(masm_hotpatch_core PROPERTIES
    OUTPUT_NAME "masm_hotpatch_core"
)

# ==== MASM Agentic Systems Library ====
# These will be stubs until implemented
set(MASM_AGENTIC_SOURCES)
foreach(src proxy_hotpatcher.asm agentic_failure_detector.asm agentic_puppeteer.asm)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        list(APPEND MASM_AGENTIC_SOURCES ${src})
    endif()
endforeach()

if(MASM_AGENTIC_SOURCES)
    add_library(masm_agentic_obj OBJECT ${MASM_AGENTIC_SOURCES})
    add_library(masm_agentic STATIC $<TARGET_OBJECTS:masm_agentic_obj>)
    set_target_properties(masm_agentic PROPERTIES
        OUTPUT_NAME "masm_agentic"
    )
endif()

# ==== MASM AI Orchestration System (NEW) ====
set(MASM_ORCHESTRATION_SOURCES
    masm_orchestration_wrapper.asm
    simple_orchestration.asm
    ai_orchestration_coordinator.asm
    agentic_inference_stream.asm
    autonomous_task_executor.asm
    agentic_failure_recovery.asm
)

# Check which files exist and only include existing ones
foreach(src ${MASM_ORCHESTRATION_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        message(WARNING "MASM source file missing: ${src}")
        list(REMOVE_ITEM MASM_ORCHESTRATION_SOURCES ${src})
    endif()
endforeach()

add_library(masm_orchestration_obj OBJECT ${MASM_ORCHESTRATION_SOURCES})
add_library(masm_orchestration STATIC $<TARGET_OBJECTS:masm_orchestration_obj>)
set_target_properties(masm_orchestration PROPERTIES
    OUTPUT_NAME "masm_orchestration"
)

# ==== MASM UI Systems Library (NEW) ====
# Output pane logging, tab management, file tree, agent chat, menu handlers, layout persistence
set(MASM_UI_SOURCES)
foreach(src output_pane_logger.asm tab_manager.asm file_tree_driver.asm agent_chat_modes.asm menu_handlers.asm layout_persistence.asm)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        list(APPEND MASM_UI_SOURCES ${src})
    endif()
endforeach()

if(MASM_UI_SOURCES)
    add_library(masm_ui_obj OBJECT ${MASM_UI_SOURCES})
    add_library(masm_ui STATIC $<TARGET_OBJECTS:masm_ui_obj>)
    set_target_properties(masm_ui PROPERTIES
        OUTPUT_NAME "masm_ui"
    )
endif()

# ==== Unified MASM Hotpatch Library (All-in-One) ====
set(MASM_UNIFIED_SOURCES ${MASM_RUNTIME_SOURCES})
list(APPEND MASM_UNIFIED_SOURCES ${MASM_QT6_FOUNDATION_SOURCES})
list(APPEND MASM_UNIFIED_SOURCES ${MASM_HOTPATCH_SOURCES})
if(MASM_AGENTIC_SOURCES)
    list(APPEND MASM_UNIFIED_SOURCES ${MASM_AGENTIC_SOURCES})
endif()

add_library(masm_hotpatch_unified_obj OBJECT ${MASM_UNIFIED_SOURCES})
add_library(masm_hotpatch_unified STATIC $<TARGET_OBJECTS:masm_hotpatch_unified_obj>)
set_target_properties(masm_hotpatch_unified PROPERTIES
    OUTPUT_NAME "masm_hotpatch_unified"
)

# ==== Pure MASM Test Harness (NO C/C++ CODE) ====
option(BUILD_MASM_TESTS "Build pure MASM hotpatch tests" ON)

if(BUILD_MASM_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/masm_test_main.asm")
    # Pure MASM x64 test harness - ZERO C/C++ dependencies
    add_executable(masm_hotpatch_test
        masm_test_main.asm
        $<TARGET_OBJECTS:masm_hotpatch_unified_obj>
    )
    
    set_target_properties(masm_hotpatch_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests"
        LINK_FLAGS "/SUBSYSTEM:CONSOLE /ENTRY:main kernel32.lib user32.lib"
    )
    
    # Add test
    enable_testing()
    add_test(NAME MASM_HotpatchSuite COMMAND masm_hotpatch_test)
    
    set_tests_properties(MASM_HotpatchSuite PROPERTIES
        PASS_REGULAR_EXPRESSION "Test Summary"
        FAIL_REGULAR_EXPRESSION "\\[FAIL\\]"
    )
endif()

# ==== Installation Targets ====
install(TARGETS masm_runtime masm_qt6_foundation masm_hotpatch_core masm_hotpatch_unified
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES masm_hotpatch.inc
    DESTINATION include/masm
)

# ==== Tools: MASM Header Generator (pure MASM) ====
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/masm_header_gen.asm")
    set_source_files_properties(tools/masm_header_gen.asm PROPERTIES LANGUAGE ASM_MASM)
    add_executable(masm_header_gen tools/masm_header_gen.asm)
    # Static link flags for a simple console app with kernel32
    set_target_properties(masm_header_gen PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LINK_FLAGS "/SUBSYSTEM:CONSOLE /ENTRY:main kernel32.lib"
    )
endif()

# ==== Tools: MASM Source Stub Generator (pure MASM) ====
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/masm_source_stub_gen.asm")
    set_source_files_properties(tools/masm_source_stub_gen.asm PROPERTIES LANGUAGE ASM_MASM)
    add_executable(masm_source_stub_gen tools/masm_source_stub_gen.asm)
    set_target_properties(masm_source_stub_gen PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LINK_FLAGS "/SUBSYSTEM:CONSOLE /ENTRY:main kernel32.lib"
    )
endif()

# ==== Build Summary ====
message(STATUS "========================================")
message(STATUS "MASM x64 Hotpatch System (PURE ASM)")
message(STATUS "========================================")
message(STATUS "Compiler: ${CMAKE_ASM_MASM_COMPILER}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output: ${CMAKE_BINARY_DIR}/lib")
message(STATUS "")
message(STATUS "Libraries (ZERO C/C++ dependencies):")
message(STATUS "  - masm_runtime")
message(STATUS "  - masm_qt6_foundation (Qt6 object model, event queue, signal/slot)")
message(STATUS "  - masm_hotpatch_core")
message(STATUS "  - masm_hotpatch_unified")
message(STATUS "")
message(STATUS "Build tests: ${BUILD_MASM_TESTS}")
message(STATUS "========================================")

# ==== Custom Build Targets ====
add_custom_target(masm_clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/lib"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/lib"
    COMMENT "Cleaning MASM build artifacts"
)

add_custom_target(masm_rebuild
    COMMAND ${CMAKE_COMMAND} --build . --target masm_clean
    COMMAND ${CMAKE_COMMAND} --build . --target masm_hotpatch_unified
    COMMENT "Rebuilding MASM hotpatch system"
)

# Target: masm_stats - Show build statistics
add_custom_target(masm_stats
    COMMAND powershell -Command "Get-ChildItem -Path src/masm/*.asm -Recurse | Measure-Object -Property Length -Sum | Select-Object Count, @{Name='TotalKB'; Expression={[math]::Round($_.Sum/1KB, 2)}}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "MASM source statistics"
)
