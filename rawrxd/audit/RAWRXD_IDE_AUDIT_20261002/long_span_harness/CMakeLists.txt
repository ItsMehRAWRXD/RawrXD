cmake_minimum_required(VERSION 3.20)
project(long_span NONE)

# AUDIT.md section 13 closed U1-U3 but left one item: U3 placed the competing
# command ADJACENT to the filter call. The real file has ~11,300 lines between the
# last rawrxd_filter_missing_sources() call (CMakeLists.txt:7313) and the end of the
# top-level scope. This asks whether span LENGTH changes the outcome.
#
#   LONG_SPAN_HARMLESS      400 commands between the violation and end of directory.
#                          Do they preempt the deferred aggregate?
#   LONG_SPAN_INTERVENING_FATAL
#                          100 harmless commands, then a configure-time
#                          message(FATAL_ERROR). Does the aggregate still print?
#
# The second case is the one that matters. If a fatal anywhere in that span wins,
# then the aggregate gate is only reachable when nothing else fails first, which is
# a materially weaker guarantee than "reports all eight lists".

set(SPAN_SIZE 400 CACHE STRING "commands to emit after the violation")

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
        "${RAWRXD_CERT_VIOLATION_COUNT} list(s):\n\n  ${_all}")
endfunction()

# The violation, as the real filter would record it.
rawrxd_declare_cert_violation("WIN32IDE_SOURCES: 225 referenced source(s) do not exist:\n  src/win32app/Win32IDE.cpp src/win32app/Win32IDE_Debugger.cpp")
rawrxd_declare_cert_violation("RAWR_ENGINE_SOURCES: 54 declared source(s) are EMPTY-BODIED:\n  src/logging/Logger.cpp")

if(MODE STREQUAL "LONG_SPAN_HARMLESS")
    # Mimic the intervening span: targets, custom targets, includes, messages.
    foreach(i RANGE ${SPAN_SIZE})
        add_library(SPAN_TARGET_${i})
        add_custom_target(SPAN_CUSTOM_${i})
        message(STATUS "MARK_SPAN_COMMAND_${i}=1")
    endforeach()
    message(STATUS "MARK_LAST_TOP_LEVEL_COMMAND=1")

elseif(MODE STREQUAL "LONG_SPAN_INTERVENING_FATAL")
    foreach(i RANGE 100)
        message(STATUS "MARK_SPAN_COMMAND_${i}=1")
    endforeach()
    message(FATAL_ERROR "[preempt] an unrelated configure-time failure later in the span")

elseif(MODE STREQUAL "LONG_SPAN_WARNING_AS_ERROR")
    # A common pattern: a warning promoted to an error.
    foreach(i RANGE 50)
        message(STATUS "MARK_SPAN_COMMAND_${i}=1")
    endforeach()
    message(WARNING "[preempt] a warning raised later in the span")

else()
    message(FATAL_ERROR "unknown MODE=${MODE}")
endif()