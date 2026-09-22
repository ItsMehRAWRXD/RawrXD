# RawrXDStrictWin32IDESourceClosure.cmake
#
# Include immediately before:
#   add_executable(RawrXD-Win32IDE WIN32 ${WIN32IDE_SOURCES} ...)
#
# Purpose:
#   1. Remove obsolete historical source names only when the file truly does not exist.
#   2. In strict production mode, remove compatibility/stub/shim/fallback/link-closure TUs.
#   3. Fail configure on every remaining missing concrete source file.
#   4. Never synthesize implementation files and never silently convert failure to success.

if(NOT DEFINED WIN32IDE_SOURCES)
    message(FATAL_ERROR
        "[StrictIDEClosure] WIN32IDE_SOURCES is not defined. "
        "Include RawrXDStrictWin32IDESourceClosure.cmake after set(WIN32IDE_SOURCES ...) "
        "and before add_executable(RawrXD-Win32IDE ...).")
endif()

set(_RAWRXD_HISTORICAL_SOURCE_NAMES
    src/ai_completion_real.cpp
    src/vulkan_kernel_bridge.cpp
    src/gguf_d3d12_bridge.cpp
    src/rdna3_bridge.cpp
    src/agentic_engine.cpp
    src/subagent_core.cpp
)

foreach(_rawrxd_legacy IN LISTS _RAWRXD_HISTORICAL_SOURCE_NAMES)
    set(_rawrxd_legacy_abs "${CMAKE_CURRENT_SOURCE_DIR}/${_rawrxd_legacy}")
    if(NOT EXISTS "${_rawrxd_legacy_abs}")
        list(REMOVE_ITEM WIN32IDE_SOURCES "${_rawrxd_legacy}")
        message(STATUS
            "[StrictIDEClosure] removed absent historical TU from IDE source list: "
            "${_rawrxd_legacy}")
    else()
        message(STATUS
            "[StrictIDEClosure] retaining real source present on disk: "
            "${_rawrxd_legacy}")
    endif()
endforeach()

# ANSIParser.cpp is different: history explicitly says its fake implementation was
# removed in favor of a real implementation.  It is therefore a required real TU.
if("src/ANSIParser.cpp" IN_LIST WIN32IDE_SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ANSIParser.cpp")
        message(FATAL_ERROR
            "[StrictIDEClosure] src/ANSIParser.cpp is required but missing. "
            "Apply RawrXD missing-source Batch 1 first.")
    endif()
endif()

if(RAWRXD_PRODUCTION_STRIP_STUB_SOURCES)
    # Exact known compatibility/link-closure units that must never establish
    # production authority.  If removing one exposes LNK2001/LNK2019, that
    # unresolved symbol becomes a real implementation obligation.
    set(_RAWRXD_STRICT_EXACT_REMOVALS
        src/core/rawrxd_linker_closure.cpp
        src/core/unlinked_symbols_batch_021.cpp
        src/deep2/MASMKernelStubs.cpp
        src/win32app/Win32IDE_headless_stubs.cpp
        src/core/agentic_executor_link_stub.cpp
        src/core/beacon_link_stub.cpp
        src/core/ssot_missing_handlers_provider.cpp
        src/core/ssot_auto_missing_handlers.cpp
        src/core/ssot_linker_gap_handlers.cpp
        src/stubs.cpp
        src/core/stubs.cpp
    )
    foreach(_rawrxd_bad IN LISTS _RAWRXD_STRICT_EXACT_REMOVALS)
        list(REMOVE_ITEM WIN32IDE_SOURCES "${_rawrxd_bad}")
    endforeach()

    # General strict policy.  The exceptions are deliberately narrow and should
    # only be added when a file with an unfortunate historical name is a proven
    # real implementation.
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_link_stub[^/]*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_link_stubs[^/]*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_shim[^/]*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_shims[^/]*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_mock[^/]*\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)[^/]*_stub\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)stubs\\.cpp$")
    list(FILTER WIN32IDE_SOURCES EXCLUDE REGEX "(^|/)unlinked_symbols_batch_[0-9]+\\.cpp$")

    # Do NOT blanket-remove "*fallback*" here.  The current tree contains some
    # historically-named files that CMake itself describes as real production
    # providers.  Those must be classified by symbol ownership, not spelling.
endif()

# Validate every remaining concrete source path before CMake reaches the target.
set(_RAWRXD_MISSING_IDE_SOURCES "")
foreach(_rawrxd_src IN LISTS WIN32IDE_SOURCES)
    # Ignore target objects and generator expressions.
    if(_rawrxd_src MATCHES "^\\$<")
        continue()
    endif()

    # Only validate translation/resource units. Headers are allowed to be listed
    # for IDE visibility without participating in compilation.
    if(NOT _rawrxd_src MATCHES "\\.(c|cc|cpp|cxx|asm|s|rc)$")
        continue()
    endif()

    if(IS_ABSOLUTE "${_rawrxd_src}")
        set(_rawrxd_abs "${_rawrxd_src}")
    else()
        set(_rawrxd_abs "${CMAKE_CURRENT_SOURCE_DIR}/${_rawrxd_src}")
    endif()

    # Generated files under the binary directory may legitimately not exist yet.
    string(FIND "${_rawrxd_abs}" "${CMAKE_CURRENT_BINARY_DIR}" _rawrxd_in_binary)
    if(_rawrxd_in_binary EQUAL 0)
        continue()
    endif()

    if(NOT EXISTS "${_rawrxd_abs}")
        list(APPEND _RAWRXD_MISSING_IDE_SOURCES "${_rawrxd_src}")
    endif()
endforeach()

if(_RAWRXD_MISSING_IDE_SOURCES)
    list(REMOVE_DUPLICATES _RAWRXD_MISSING_IDE_SOURCES)
    list(SORT _RAWRXD_MISSING_IDE_SOURCES)
    string(JOIN "\n  - " _rawrxd_missing_text ${_RAWRXD_MISSING_IDE_SOURCES})
    message(FATAL_ERROR
        "[StrictIDEClosure] unresolved concrete IDE source files remain:\n"
        "  - ${_rawrxd_missing_text}\n"
        "Do not create empty/stub files. Implement against a live header/caller or "
        "remove a proven obsolete source-list entry.")
endif()

list(REMOVE_DUPLICATES WIN32IDE_SOURCES)
list(LENGTH WIN32IDE_SOURCES _rawrxd_ide_source_count)
message(STATUS
    "[StrictIDEClosure] WIN32IDE source closure passed: "
    "${_rawrxd_ide_source_count} concrete/listed units remain.")
