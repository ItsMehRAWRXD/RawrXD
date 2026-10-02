cmake_minimum_required(VERSION 3.20)
project(defer_semantics NONE)

# RAWRXD_GATE_AGGREGATION_001 - integration-semantics harness
#
# AUDIT.md section 12 lists three unknowns that the gate_harness cannot answer,
# because gate_harness only reproduces the aggregation logic. These three are
# about CMake behaviour, so they are answerable here, on the same generator and
# the same CMake as the real configure.
#
#   U1  Does cmake_language(DEFER DIRECTORY ...) fire at end of directory scope?
#   U2  Does message(FATAL_ERROR) inside a deferred call still abort configure?
#   U3  Do add_library()/add_executable() with an empty source list error BEFORE
#       a later deferred fatal, making the gate's message the last one seen?
#
# Two further risks in the proposed patch that nobody had tested:
#   R1  The patch calls cmake_language(DEFER ...) from INSIDE a function. If DEFER
#       is directory-scope-only, the patch is broken.
#   R2  The patch registers DEFER once behind a CACHE INTERNAL guard, called from
#       eight separate filter invocations. If the guard or the scope is wrong, the
#       aggregate may fire zero times or eight times.
#
# MODE selects the case. Each prints an explicit marker so the log is self-reading.

if(NOT MODE)
    message(FATAL_ERROR "MODE is required")
endif()

# --- the accumulator exactly as proposed in RAWRXD_GATE_AGGREGATION_001 --------
# CORRECTED after measurement: named parameter (not ARGV1, which is empty here)
# and a newline sentinel (CACHE INTERNAL truncates at the first newline).
function(rawrxd_declare_cert_violation msg)
    math(EXPR _vc "${RAWRXD_CERT_VIOLATION_COUNT} + 1")
    set(RAWRXD_CERT_VIOLATION_COUNT ${_vc} CACHE INTERNAL "" FORCE)
    string(REPLACE "\n" "@@RAWRXD_NL@@" _enc "${msg}")
    set(RAWRXD_CERT_VIOLATIONS "${RAWRXD_CERT_VIOLATIONS}|||${_enc}"
        CACHE INTERNAL "" FORCE)
    if(RAWRXD_CERT_VIOLATION_DEFERRED)
        return()
    endif()
    set(RAWRXD_CERT_VIOLATION_DEFERRED TRUE CACHE INTERNAL "" FORCE)
    cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
                   CALL rawrxd_raise_cert_violations)
endfunction()

function(rawrxd_raise_cert_violations)
    message(STATUS "MARK_RAISE_ENTERED=1")
    if(NOT RAWRXD_CERT_VIOLATION_COUNT)
        message(STATUS "MARK_RAISE_NO_VIOLATIONS=1")
        return()
    endif()
    string(REPLACE "|||" "\n\n  " _all "${RAWRXD_CERT_VIOLATIONS}")
    string(REPLACE "@@RAWRXD_NL@@" "\n  " _all "${_all}")
    string(STRIP "${_all}" _all)
    message(FATAL_ERROR
        "[rawrxd_cert_violations] source closure failed in "
        "${RAWRXD_CERT_VIOLATION_COUNT} list(s). Every offending list is listed "
        "below; this gate reports all of them rather than stopping at the first.\n\n"
        "  ${_all}")
endfunction()

if(MODE STREQUAL "U1_TIMING")
    # U1 + R1: register from inside a function, then run more top-level commands.
    rawrxd_declare_cert_violation("list one violated")
    message(STATUS "MARK_AFTER_DECLARE=1")
    rawrxd_declare_cert_violation("list two violated")
    message(STATUS "MARK_AFTER_SECOND_DECLARE=1")
    message(STATUS "MARK_LAST_TOP_LEVEL_COMMAND=1")
elseif(MODE STREQUAL "U2_FATAL_IN_DEFER")
    # U2 + R2: three violations from three separate "filter" calls.
    rawrxd_declare_cert_violation("LIST_A violated: 2 missing\n  src/win32app/Win32IDE.cpp src/win32app/Win32IDE_Debugger.cpp")
    rawrxd_declare_cert_violation("LIST_B violated: 1 missing\n  src/lsp/RawrXD_LSPServer.cpp")
    rawrxd_declare_cert_violation("LIST_C EMPTY-BODIED: 2 files\n  src/logging/Logger.cpp src/vulkan_compute.cpp")
    message(STATUS "MARK_LAST_TOP_LEVEL_COMMAND=1")
elseif(MODE STREQUAL "U3_EMPTY_TARGET")
    # U3: an empty-source target is created BEFORE the deferred raise can fire.
    add_library(EMPTY_TARGET)
    rawrxd_declare_cert_violation("LIST_A violated: 2 missing\n  src/win32app/Win32IDE.cpp src/win32app/Win32IDE_Debugger.cpp")
    message(STATUS "MARK_LAST_TOP_LEVEL_COMMAND=1")
elseif(MODE STREQUAL "CONTROL_CLEAN")
    # Control: the deferred call is registered but nothing violates.
    rawrxd_raise_cert_violations()
    message(STATUS "MARK_LAST_TOP_LEVEL_COMMAND=1")
else()
    message(FATAL_ERROR "unknown MODE=${MODE}")
endif()
