cmake_minimum_required(VERSION 3.20)
project(gate_aggregation_harness NONE)

# ---------------------------------------------------------------------------
# RAWRXD_GATE_AGGREGATION_001 - isolated verification harness
#
# Purpose: prove the mechanism that rawrxd_filter_missing_sources needs, without
# touching F:\~dev\rawrxd\CMakeLists.txt. That file is modified by another lane
# and GREW 40 lines during this audit (18619 -> 18659), so a multi-site patch
# cannot be applied or regression-tested here without risking a concurrent-write
# collision.
#
# Two modes, selected by MODE:
#   MODE=FAILFAST    - current behaviour: FATAL_ERROR inside the filter function,
#                      i.e. at the FIRST offending list.
#   MODE=AGGREGATE   - proposed behaviour: every violation is accumulated and
#                      raised once, after all lists have been filtered.
#
# Fixtures, selected by FIXTURE:
#   FIXTURE=VIOLATING - list1 has a missing source, list2 has an empty-bodied TU
#   FIXTURE=CLEAN     - every declared source exists and contains code
#
# The CLEAN case is the falsification test: an aggregate gate that fires on a
# healthy tree is worse than no gate, because it would train everyone to ignore it.
# ---------------------------------------------------------------------------

set(FIXTURE_DIR "${CMAKE_CURRENT_LIST_DIR}/fixtures/${FIXTURE}")

# --- the rule under test, transcribed from CMakeLists.txt:266-377 ------------
function(rawrxd_filter_missing_sources list_var)
    set(_kept)
    set(_dropped 0)
    set(_dropped_names)
    set(_emptybodied 0)
    set(_emptybodied_names)

    foreach(_src IN LISTS ${list_var})
        set(_path "${CMAKE_CURRENT_LIST_DIR}/fixtures/${FIXTURE}/${_src}")
        if(NOT EXISTS "${_path}")
            math(EXPR _dropped "${_dropped} + 1")
            list(APPEND _dropped_names "${_src}")
            continue()
        endif()

        file(READ "${_path}" _body LIMIT 65536)
        string(REGEX REPLACE "/\\*([^*]|\\*[^/])*\\*/" " " _body "${_body}")
        string(REGEX REPLACE "//[^\n]*" " " _body "${_body}")
        string(REGEX REPLACE "#[^\n]*" " " _body "${_body}")
        if(NOT (_body MATCHES "[;{}()=]"))
            math(EXPR _emptybodied "${_emptybodied} + 1")
            list(APPEND _emptybodied_names "${_src}")
            continue()
        endif()
        list(APPEND _kept "${_src}")
    endforeach()

    if(_emptybodied GREATER 0)
        string(REPLACE ";" " " _eb "${_emptybodied_names}")
        if(MODE STREQUAL "FAILFAST")
            message(FATAL_ERROR
                "[release_cert_source_closure] ${list_var}: ${_emptybodied} declared source(s) are "
                "EMPTY-BODIED (no code survives comment stripping):\n  ${_eb}")
        else()
            set(_msg "[release_cert_source_closure] ${list_var}: ${_emptybodied} declared source(s) are EMPTY-BODIED:\n  ${_eb}")
            math(EXPR _n "${RAWRXD_HARNESS_VIOLATION_COUNT} + 1")
            set(RAWRXD_HARNESS_VIOLATION_COUNT ${_n} CACHE INTERNAL "" FORCE)
            set(RAWRXD_HARNESS_VIOLATIONS "${RAWRXD_HARNESS_VIOLATIONS}|||${_msg}" CACHE INTERNAL "" FORCE)
        endif()
    endif()

    if(_dropped GREATER 0)
        string(REPLACE ";" " " _dr "${_dropped_names}")
        if(MODE STREQUAL "FAILFAST")
            message(FATAL_ERROR
                "[rawrxd_filter_missing_sources] ${list_var}: ${_dropped} referenced source(s) "
                "do not exist:\n  ${_dr}")
        else()
            set(_msg "[rawrxd_filter_missing_sources] ${list_var}: ${_dropped} referenced source(s) do not exist:\n  ${_dr}")
            math(EXPR _n "${RAWRXD_HARNESS_VIOLATION_COUNT} + 1")
            set(RAWRXD_HARNESS_VIOLATION_COUNT ${_n} CACHE INTERNAL "" FORCE)
            set(RAWRXD_HARNESS_VIOLATIONS "${RAWRXD_HARNESS_VIOLATIONS}|||${_msg}" CACHE INTERNAL "" FORCE)
        endif()
    endif()
endfunction()

# --- three lists, in the same relative order as the real call sites -----------
set(LIST_A src/a.cpp)        # clean
set(LIST_B src/missing.cpp)   # absent  -> violation under AGGREGATE
set(LIST_C src/empty.cpp)     # empty   -> violation under AGGREGATE

rawrxd_filter_missing_sources(LIST_A)
rawrxd_filter_missing_sources(LIST_B)
rawrxd_filter_missing_sources(LIST_C)

# --- the aggregate raise, which the real file would place after the last call -
if(NOT MODE STREQUAL "FAILFAST")
    if(RAWRXD_HARNESS_VIOLATION_COUNT GREATER 0)
        string(REPLACE "|||" "\n\n  " _all "${RAWRXD_HARNESS_VIOLATIONS}")
        string(STRIP "${_all}" _all)
        message(FATAL_ERROR
            "[rawrxd_cert_violations] source-closure failed in "
            "${RAWRXD_HARNESS_VIOLATION_COUNT} list(s):\n\n  ${_all}")
    else()
        message(STATUS "HARNESS_CLEAN_TREE_NO_VIOLATION=1")
    endif()
endif()

message(STATUS "HARNESS_REACHED_END=1")