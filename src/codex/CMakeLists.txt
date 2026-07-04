# RawrXD Codex Module - CMake Build Configuration
# Zero-dependency Win32 HTTP client with auto-detecting CLI/GUI entry point

cmake_minimum_required(VERSION 3.20)

# Check if building with full IDE (UnifiedSessionState available)
if(TARGET UnifiedSessionState OR EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../core/UnifiedSessionState.hpp")
    set(RAWRXD_CODEX_EVENTBUS_ENABLED ON)
    message(STATUS "[Codex] EventBus integration enabled (UnifiedSessionState found)")
else()
    set(RAWRXD_CODEX_EVENTBUS_ENABLED OFF)
    message(STATUS "[Codex] EventBus integration disabled (standalone build)")
endif()

# Codex module - core sources always included
set(CODEX_SOURCES
    main.cpp
    CodexCLI.cpp
    CodexGUI.cpp
    HttpClient.cpp
    ../core/Version.cpp
)

set(CODEX_HEADERS
    CodexCLI.hpp
    CodexGUI.hpp
    HttpClient.hpp
    JsonLite.hpp
)

# Optional event bus integration
if(RAWRXD_CODEX_EVENTBUS_ENABLED)
    list(APPEND CODEX_SOURCES CodexEventBridge.cpp CodexEventBus.cpp)
    list(APPEND CODEX_HEADERS CodexEventBridge.hpp CodexEventBus.hpp)
endif()

# Command handlers (always included)
list(APPEND CODEX_SOURCES CodexCommandHandlers.cpp)
list(APPEND CODEX_HEADERS CodexCommandHandlers.hpp)

# LSP Bridge for IDE integration
list(APPEND CODEX_SOURCES CodexLSPBridge.cpp)
list(APPEND CODEX_HEADERS CodexLSPBridge.hpp)

# Chat Bridge for IDE chat panel integration
list(APPEND CODEX_SOURCES CodexChatBridge.cpp)
list(APPEND CODEX_HEADERS CodexChatBridge.hpp)

# Autocomplete Provider for IDE completion system
list(APPEND CODEX_SOURCES CodexAutocompleteProvider.cpp)
list(APPEND CODEX_HEADERS CodexAutocompleteProvider.hpp)

# Settings Manager
list(APPEND CODEX_SOURCES CodexSettings.cpp)
list(APPEND CODEX_HEADERS CodexSettings.hpp)

# Menu Integration
list(APPEND CODEX_SOURCES CodexMenuIntegration.cpp)
list(APPEND CODEX_HEADERS CodexMenuIntegration.hpp)

# Settings Dialog
list(APPEND CODEX_SOURCES CodexSettingsDialog.cpp)
list(APPEND CODEX_HEADERS CodexSettingsDialog.hpp)

# Windows-specific executable
if(WIN32)
    # Create unified executable that auto-detects console vs GUI
    add_executable(rawrxd-codex ${CODEX_SOURCES} ${CODEX_HEADERS})
    
    # Set as Windows GUI application but with console fallback
    set_target_properties(rawrxd-codex PROPERTIES
        WIN32_EXECUTABLE TRUE
        OUTPUT_NAME "rawrxd-codex"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    
    # Include directories
    target_include_directories(rawrxd-codex PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../core
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    )
    
    # Enable event bus integration if available
    if(RAWRXD_CODEX_EVENTBUS_ENABLED)
        target_compile_definitions(rawrxd-codex PRIVATE RAWRXD_ENABLE_CODEX_EVENTBUS)
    endif()
    
    # Compiler flags for maximum performance
    if(MINGW OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(rawrxd-codex PRIVATE
            -O3              # Optimize for speed
            -Wall            # All warnings
            -Wextra          # Extra warnings
            -mwindows        # Windows subsystem
            -municode        # Unicode entry point
        )
        
        # Static linking for MinGW
        target_link_options(rawrxd-codex PRIVATE
            -static-libgcc
            -static-libstdc++
        )
        
        # MinGW libraries
        target_link_libraries(rawrxd-codex PRIVATE
            winhttp
            user32
            gdi32
            shell32
            comctl32
        )
    elseif(MSVC)
        # MSVC flags - inherit optimization from parent, add our specific flags
        target_compile_options(rawrxd-codex PRIVATE
            /W4              # High warning level
            /EHsc            # Exception handling
            /DWIN32_LEAN_AND_MEAN
            /DUNICODE
            /D_UNICODE
        )
        
        # MSVC specific optimizations (Release only)
        target_compile_options(rawrxd-codex PRIVATE
            $<$<CONFIG:Release>:/GS->         # Disable buffer security checks (performance)
            $<$<CONFIG:Release>:/GL>            # Whole program optimization
            $<$<CONFIG:Release>:/Gw>           # Optimize global data
        )
        
        target_link_options(rawrxd-codex PRIVATE
            $<$<CONFIG:Release>:/LTCG>           # Link-time code generation
            $<$<CONFIG:Release>:/OPT:REF>        # Eliminate unreferenced functions
            $<$<CONFIG:Release>:/OPT:ICF>       # Identical COMDAT folding
        )
        
        # MSVC libraries
        target_link_libraries(rawrxd-codex PRIVATE
            winhttp.lib
            user32.lib
            gdi32.lib
            shell32.lib
            comctl32.lib
        )
    endif()
endif()

# Installation
install(TARGETS rawrxd-codex
    RUNTIME DESTINATION bin
)
