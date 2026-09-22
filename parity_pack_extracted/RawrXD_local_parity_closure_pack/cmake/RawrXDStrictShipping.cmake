# RawrXD strict shipping closure gate.
# Include AFTER add_executable(RawrXD-Win32IDE ...), then:
#   rawrxd_enforce_shipping_target(RawrXD-Win32IDE)
#
# Optional semicolon-separated source-path allowlist for intentionally named files:
#   set(RAWRXD_SHIPPING_ALLOWLIST "src/legitimate_test_protocol.cpp")

set(FETCHCONTENT_FULLY_DISCONNECTED ON CACHE BOOL
    "Shipping builds may not download dependencies" FORCE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Shipping builds may not update dependencies" FORCE)

function(rawrxd_enforce_shipping_target target)
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "RawrXD strict gate: target '${target}' does not exist")
    endif()

    get_target_property(_srcs "${target}" SOURCES)
    if(NOT _srcs)
        message(FATAL_ERROR "RawrXD strict gate: '${target}' has no SOURCES")
    endif()

    set(_entrypoints 0)
    set(_entry_files "")
    foreach(_src IN LISTS _srcs)
        # Generator expressions are resolved later; do not pretend they are disk paths.
        if(_src MATCHES "^\\$<")
            continue()
        endif()

        if(IS_ABSOLUTE "${_src}")
            set(_abs "${_src}")
        else()
            get_filename_component(_abs "${_src}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
        endif()

        get_filename_component(_ext "${_abs}" EXT)
        string(TOLOWER "${_ext}" _ext)
        if(_ext STREQUAL ".cpp" OR _ext STREQUAL ".cc" OR _ext STREQUAL ".cxx" OR _ext STREQUAL ".c")
            if(NOT EXISTS "${_abs}")
                message(FATAL_ERROR "RawrXD strict gate: ghost source: ${_src}")
            endif()

            file(TO_CMAKE_PATH "${_src}" _norm)
            string(TOLOWER "${_norm}" _low)
            set(_allowed FALSE)
            foreach(_allow IN LISTS RAWRXD_SHIPPING_ALLOWLIST)
                file(TO_CMAKE_PATH "${_allow}" _allow_norm)
                string(TOLOWER "${_allow_norm}" _allow_low)
                if(_low STREQUAL _allow_low)
                    set(_allowed TRUE)
                endif()
            endforeach()

            if(NOT _allowed AND
               _low MATCHES "(^|/)(tests?|examples?|demos?|benchmarks?)(/|$)|(^|/)[^/]*(stub|mock|fake|placeholder|unlinked_symbols)[^/]*\\.(c|cc|cpp|cxx)$")
                message(FATAL_ERROR
                    "RawrXD strict gate: non-shipping/stub authority in '${target}': ${_src}")
            endif()

            file(READ "${_abs}" _body)
            # Count actual WinMain-family definitions conservatively.
            if(_body MATCHES "(^|[\n\r])[ \t]*(int|INT|signed[ \t]+int)[ \t]+(WINAPI[ \t]+|APIENTRY[ \t]+)?(wWinMain|WinMain)[ \t]*\\(")
                math(EXPR _entrypoints "${_entrypoints}+1")
                list(APPEND _entry_files "${_src}")
            endif()
        endif()
    endforeach()

    if(NOT _entrypoints EQUAL 1)
        string(JOIN ", " _entry_joined ${_entry_files})
        message(FATAL_ERROR
            "RawrXD strict gate: expected exactly 1 WinMain-family definition in '${target}', "
            "found ${_entrypoints}: ${_entry_joined}")
    endif()

    target_compile_definitions("${target}" PRIVATE
        RAWRXD_STRICT_AGENTIC_REALITY=1
        RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=0
        RAWRXD_ENABLE_MISSING_HANDLER_STUBS=0)

    message(STATUS "RawrXD strict shipping gate PASS for ${target}")
endfunction()
