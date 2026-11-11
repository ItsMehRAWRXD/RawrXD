cmake_minimum_required(VERSION 3.16)
project(rawrxd_extension_runtime C CXX)

# ============================================================================
#  Shared VS Code extension runtime.
#
#  This library is the single implementation of the extension subsystem. Both
#  front ends link it:
#
#    * the Win32 IDE links it for the Extensions panel and the marketplace
#    * the command line links it for `rawr plugin ...`
#
#  Nothing in here is duplicated per front end. The registry, the installer,
#  the JavaScript host and the VS Code API shim all live here.
#
#  The sources are recovered from the RawrXD source drop. See
#  G:\VSC0de\certification\recover_extension_sources.ps1.
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The recovered sources live in the main RawrXD source tree so that the IDE
# and the command line can both reach them.
get_filename_component(RAWRXD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

if(NOT EXISTS "${RAWRXD_ROOT}/src/marketplace/extension_marketplace.cpp")
    message(FATAL_ERROR
        "The extension sources are not present under ${RAWRXD_ROOT}/src. "
        "Run G:\\VSC0de\\certification\\recover_extension_sources.ps1 first.")
endif()

set(RAWRXD_SRC "${RAWRXD_ROOT}/src")
set(RAWRXD_INC "${RAWRXD_ROOT}/include")

# The source list below is written relative to the RawrXD root.
set(RAWRXD_SOURCE_ROOT "${RAWRXD_ROOT}")

# ---------------------------------------------------------------------------
# QuickJS
#
# The extension host needs a real JavaScript engine. Without it the host
# falls back to stubs that return constants instead of executing anything,
# so an extension appears to load but never runs.
# ---------------------------------------------------------------------------
set(QUICKJS_DIR "${RAWRXD_ROOT}/3rdparty/quickjs_ng")
set(RAWRXD_HAS_QUICKJS OFF)
if(EXISTS "${QUICKJS_DIR}/quickjs.c" AND EXISTS "${QUICKJS_DIR}/quickjs.h")
    # The engine is built from several translation units. libregexp and
    # libunicode supply the regular expression and Unicode tables that
    # quickjs.c references.
    set(QUICKJS_SOURCES "${QUICKJS_DIR}/quickjs.c")
    foreach(extra libregexp.c libunicode.c dtoa.c unicode_gen.c cutils.c)
        if(EXISTS "${QUICKJS_DIR}/${extra}")
            list(APPEND QUICKJS_SOURCES "${QUICKJS_DIR}/${extra}")
        endif()
    endforeach()

    add_library(quickjs_static STATIC ${QUICKJS_SOURCES})
    set_property(TARGET quickjs_static PROPERTY C_STANDARD 11)
    set_property(TARGET quickjs_static PROPERTY C_STANDARD_REQUIRED ON)
    target_include_directories(quickjs_static PUBLIC
        "${QUICKJS_DIR}"
        "${QUICKJS_DIR}/quickjs")
    target_compile_definitions(quickjs_static PUBLIC
        CONFIG_VERSION="2024-01-13"
        VERSION="2024-01-13"
        _GNU_SOURCE
        CONFIG_BIGNUM
        _WINDOWS
        _WIN32)
    if(MSVC)
        target_compile_options(quickjs_static PRIVATE /W0 /wd4996 /wd4244 /wd4267 /wd4018)
        target_compile_definitions(quickjs_static PUBLIC _CRT_SECURE_NO_WARNINGS)
    endif()
    set(RAWRXD_HAS_QUICKJS ON)
    message(STATUS "QuickJS: enabled (${QUICKJS_DIR})")
else()
    message(WARNING
        "QuickJS: NOT found at ${QUICKJS_DIR}. The extension host will fall "
        "back to its stub implementation and will not execute JavaScript.")
endif()

# ---------------------------------------------------------------------------
# The shared runtime
# ---------------------------------------------------------------------------
set(EXTENSION_RUNTIME_SOURCES
    src/core/js_extension_host.cpp
    src/core/extension_polyfill_engine.cpp
    src/modules/vscode_extension_api.cpp
    src/marketplace/extension_marketplace.cpp
    src/marketplace/vsix_installer.cpp
    src/marketplace/offline_cache_store.cpp
    src/marketplace/enterprise_policy_engine.cpp
    src/core/runtime_cert.cpp
    src/core/zip_reader.cpp
    src/core/headless_extension_host_bridge.cpp
    src/cli/cli_extension_commands.cpp)

# Three files are deliberately not part of the shared runtime:
#
#   modules/quickjs_extension_host.cpp    an older generation of the
#   modules/quickjs_vscode_bindings.cpp   JavaScript host. The current
#   modules/quickjs_node_shims.cpp        host is core/js_extension_host.cpp,
#                                         which links the real QuickJS
#                                         engine and declares JSExtensionHost.
#
#   marketplace_ui_view.cpp               a Qt widget; it belongs to the GUI
#                                         target so that the command line does
#                                         not have to pull in Qt.
#
#   extension_marketplace_manager.cpp     the recovered copy in the source drop
#                                         is damaged (its constructor reads
#                                         "new void*(this)" and
#                                         "new // Timer(this)"), and it is a
#                                         GUI-layer class. The shared registry
#                                         is ExtensionMarketplace, which is
#                                         in the runtime.

set(EXTENSION_RUNTIME_EXISTS)
foreach(f ${EXTENSION_RUNTIME_SOURCES})
    if(EXISTS "${RAWRXD_SOURCE_ROOT}/${f}")
        list(APPEND EXTENSION_RUNTIME_EXISTS "${RAWRXD_SOURCE_ROOT}/${f}")
    else()
        message(WARNING "extension runtime: missing ${f}")
    endif()
endforeach()

add_library(rawrxd_extension_runtime STATIC ${EXTENSION_RUNTIME_EXISTS})

target_include_directories(rawrxd_extension_runtime PUBLIC
    "${RAWRXD_SRC}"
    "${RAWRXD_SRC}/core"
    "${RAWRXD_SRC}/modules"
    "${RAWRXD_SRC}/marketplace"
    "${RAWRXD_SRC}/cli"
    "${RAWRXD_SRC}/project_wizard"   # agent_esp.hpp
    "${RAWRXD_INC}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

# The extension API shim includes vulkan_compute.h, which needs the Vulkan
# headers. The SDK is discovered rather than hard coded so that a machine
# without it still builds the parts that do not need it.
file(GLOB RAWRXD_VULKAN_INCLUDE_DIRS
    "C:/VulkanSDK/*/Include"
    "C:/VulkanSDK/Include")
foreach(dir ${RAWRXD_VULKAN_INCLUDE_DIRS})
    if(EXISTS "${dir}/vulkan/vulkan.h")
        target_include_directories(rawrxd_extension_runtime PUBLIC "${dir}")
        message(STATUS "Vulkan headers: ${dir}")
        break()
    endif()
endforeach()

if(RAWRXD_HAS_QUICKJS)
    target_compile_definitions(rawrxd_extension_runtime PUBLIC RAWRXD_HAS_QUICKJS=1)
    target_link_libraries(rawrxd_extension_runtime PUBLIC quickjs_static)
endif()

if(MSVC)
    target_compile_options(rawrxd_extension_runtime PRIVATE /W0 /wd4996 /wd4244 /wd4267)
    target_compile_definitions(rawrxd_extension_runtime PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

target_link_libraries(rawrxd_extension_runtime PUBLIC
    shlwapi
    shell32
    wintrust
    crypt32
    ole32
    uuid)

# ---------------------------------------------------------------------------
# The command line front end
# ---------------------------------------------------------------------------
add_executable(rawr-plugin
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cli_main.cpp"
    "${RAWRXD_SRC}/cli/cli_extension_commands.cpp")

target_link_libraries(rawr-plugin PRIVATE rawrxd_extension_runtime)
if(MSVC)
    target_compile_options(rawr-plugin PRIVATE /W0)
endif()

# ---------------------------------------------------------------------------
# The certification
# ---------------------------------------------------------------------------
add_executable(rawr-extension-cert
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/extension_cert.cpp")
target_link_libraries(rawr-extension-cert PRIVATE rawrxd_extension_runtime)
if(MSVC)
    target_compile_options(rawr-extension-cert PRIVATE /W0)
endif()

enable_testing()
add_test(NAME RAWRXD_EXTENSION_RUNTIME_001
         COMMAND rawr-extension-cert)
