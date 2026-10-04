# ===========================================================================
# RAWRXD_SOURCE_GRAPH_001 -- declared-architecture census.
#
# INSTRUMENTATION ONLY. It creates no target, gates nothing, returns no error,
# and cannot fail a configure. Its sole job is to make the build graph's real
# state visible on every configure instead of only by reading 1.25 MB of CMake
# by hand.
#
# MEASURED BEFORE THIS MODULE EXISTED:
#     DECLARED_UNIQUE = 1393
#     PRESENT         = 1038
#     ABSENT          =  355   (25.5% of the declared graph)
#     COMMENTED_OUT   =  325
#     of which ABSENT .cpp = 354, and src/win32app accounted for 173 (48.7%)
#
# WHY IT EXISTS. A `#`-commented source reference is invisible to every static
# analysis tool and to every build gate, so a target can be long and green
# while naming none of its sources. That is a false green, and it was the
# largest single source of divergence between what the project claims to be and
# what actually gets built.
#
# COMPLETION METRIC. RAWRXD_GRAPH_SOURCES_ABSENT is expected to fall as the
# graph is materialised and then IMPLEMENTED. A materialised-but-empty
# translation unit counts as PRESENT but carries the marker
# RAWRXD_GRAPH_RESTORED_001, so structural completeness can never be read as
# functional completeness. That count is reported on every configure precisely
# so the gap between "the file exists" and "the feature works" stays visible.
# ===========================================================================

set(_SG_SELF "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt")
if(NOT EXISTS "${_SG_SELF}")
    message(STATUS "RAWRXD_SOURCE_GRAPH_001=UNAVAILABLE (no CMakeLists.txt to census)")
    return()
endif()
file(READ "${_SG_SELF}" _SG_TEXT)

# RAWRXD_SOURCE_GRAPH_COMMENT_CLASSIFIER_001
#
# A `#` comment in CMake runs to END OF LINE. The previous classifier only
# recognised a commented path when it appeared immediately after `#` plus
# optional blanks:
#
#     string(REGEX MATCHALL "#[ \t]*[A-Za-z0-9_./-]+\\.(cpp|...|asm|rc)" ...)
#
# A path named later in the same comment sentence did not match, so the
# active-token scan at line 40 claimed it and it was never subtracted. Measured
# false positive on this tree:
#
#     CMakeLists.txt:8159
#       # line tokenizer. Replaces src/core/monaco_core_stubs.cpp, which
#
# `src/core/monaco_core_stubs.cpp` is referenced ONLY inside that comment, yet it
# was classified ABSENT_ACTIVE_REF while `src/unresolved_asm_stubs.asm` -- in
# exactly the same situation, referenced only in comments -- was correctly
# classified ABSENT_COMMENTED_REF. Same fact, two answers, and the wrong one is
# the one that would fail a configure under RAWRXD_STRICT_SOURCES=ON over a file
# no target builds.
#
# The fix is to stop pattern-matching where a comment starts. Comments are
# stripped first, by line, and the two scans then run over disjoint text:
#   _SG_CODE      = every line with its '#'-to-EOL tail removed  -> active
#   _SG_COMMENTED = the removed tails                          -> commented
# A path can no longer be both, and neither scan can miss a mention.
string(REGEX MATCHALL "[^\n]*" _SG_LINES "${_SG_TEXT}")
set(_SG_CODE "")
set(_SG_COMTEXT "")
foreach(_ln IN LISTS _SG_LINES)
    # Keep a sentinel newline so the code text stays line-structured; without it
    # two adjacent lines would concatenate and fuse the tail of one onto the
    # head of the next.
    string(REGEX REPLACE "#([^\n]*)" "\n" _ln_split "${_ln}\n")
    string(REGEX REPLACE "#([^\n]*)" "" _ln_code "${_ln}")
    string(APPEND _SG_CODE "${_ln_code}\n")
    if(_ln MATCHES "#([^\n]*)")
        set(_ln_com "${CMAKE_MATCH_1}")
        string(APPEND _SG_COMTEXT "${_ln_com}\n")
    endif()
endforeach()

# --- active references ------------------------------------------------------
# Paths in _SG_CODE only: a comment can no longer contribute to this list.
string(REGEX MATCHALL "[A-Za-z0-9_./-]+\\.(cpp|hpp|h|cc|cxx|asm|rc)"
       _SG_TOKENS "${_SG_CODE}")
set(_SG_ACTIVE "")
foreach(_t IN LISTS _SG_TOKENS)
    if(_t MATCHES "^(src|tools|certs|tests|include|examples|3rdparty)/")
        list(APPEND _SG_ACTIVE "${_t}")
    endif()
endforeach()
if(_SG_ACTIVE)
    list(REMOVE_DUPLICATES _SG_ACTIVE)
endif()

# --- commented references ---------------------------------------------------
# Paths anywhere inside a removed comment tail. The '#' is gone, so no
# strip-and-retest is needed and a path in mid-sentence is now found.
string(REGEX MATCHALL "[A-Za-z0-9_./-]+\\.(cpp|hpp|h|cc|cxx|asm|rc)"
       _SG_CHITS "${_SG_COMTEXT}")
set(_SG_COMMENTED "")
foreach(_h IN LISTS _SG_CHITS)
    if(_h MATCHES "^(src|tools|certs|tests|include|examples|3rdparty)/")
        list(APPEND _SG_COMMENTED "${_h}")
    endif()
endforeach()
if(_SG_COMMENTED)
    list(REMOVE_DUPLICATES _SG_COMMENTED)
endif()

# --- classify --------------------------------------------------------------
set(_SG_PRESENT 0)
set(_SG_ABSENT 0)
set(_SG_ABSENT_CPP 0)
set(_SG_RESTORED 0)
set(_SG_ACTIVE_MISSING 0)
set(_SG_COMMENTED_MISSING 0)
set(_SG_COMMENTED_PRESENT 0)
set(_SG_AREA "")
set(_SG_ROWS "")

foreach(_p IN LISTS _SG_ACTIVE)
    set(_exists 0)
    set(_disp "")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_p}")
        set(_exists 1)
        math(EXPR _SG_PRESENT "${_SG_PRESENT} + 1")
        file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${_p}" _probe)
        if(_probe MATCHES "RAWRXD_GRAPH_RESTORED_001")
            math(EXPR _SG_RESTORED "${_SG_RESTORED} + 1")
            set(_disp "GRAPH_RESTORED_EMPTY")
        else()
            set(_disp "IMPLEMENT")
        endif()
    else()
        math(EXPR _SG_ABSENT "${_SG_ABSENT} + 1")
        if(_p MATCHES "\\.cpp$")
            math(EXPR _SG_ABSENT_CPP "${_SG_ABSENT_CPP} + 1")
        endif()
        list(FIND _SG_COMMENTED "${_p}" _cif)
        if(_cif GREATER_EQUAL 0)
            set(_disp "ABSENT_COMMENTED_REF")
            math(EXPR _SG_COMMENTED_MISSING "${_SG_COMMENTED_MISSING} + 1")
        else()
            set(_disp "ABSENT_ACTIVE_REF")
            math(EXPR _SG_ACTIVE_MISSING "${_SG_ACTIVE_MISSING} + 1")
        endif()
        # concentration by area
        string(REGEX REPLACE "^([^/]+/[^/]+)/.*$" "\\1" _ar "${_p}")
        set(_hit FALSE)
        foreach(_e IN LISTS _SG_AREA)
            string(REGEX MATCH "^(.+):([0-9]+)$" _m "${_e}")
            if("${CMAKE_MATCH_1}" STREQUAL "${_ar}")
                math(EXPR _n "${CMAKE_MATCH_2} + 1")
                list(REMOVE_ITEM _SG_AREA "${_e}")
                list(APPEND _SG_AREA "${_ar}:${_n}")
                set(_hit TRUE)
                break()
            endif()
        endforeach()
        if(NOT _hit)
            list(APPEND _SG_AREA "${_ar}:1")
        endif()
    endif()
    string(REGEX REPLACE "^([^/]+/[^/]+)/.*$" "\\1" _ar2 "${_p}")
    list(APPEND _SG_ROWS "${_p}\t${_ar2}\t${_exists}\t${_disp}")
endforeach()

foreach(_p IN LISTS _SG_COMMENTED)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_p}")
        # A commented reference to a REAL file is the build excluding source that
        # is sitting on disk -- the most misleading case, because the file is
        # present and a reader will assume it is built.
        math(EXPR _SG_COMMENTED_PRESENT "${_SG_COMMENTED_PRESENT} + 1")
    endif()
endforeach()

list(LENGTH _SG_ACTIVE _SG_DECLARED)
list(LENGTH _SG_COMMENTED _SG_NCOMMENTED)
if(_SG_DECLARED GREATER 0)
    math(EXPR _SG_PCT_PRESENT "(${_SG_PRESENT} * 1000) / ${_SG_DECLARED} / 10")
    math(EXPR _SG_PCT_ABSENT "(${_SG_ABSENT} * 1000) / ${_SG_DECLARED} / 10")
else()
    set(_SG_PCT_PRESENT 0)
    set(_SG_PCT_ABSENT 0)
endif()
if(_SG_AREA)
    list(SORT _SG_AREA)
endif()

message(STATUS "")
message(STATUS "=== RAWRXD_GRAPH_CENSUS_001 ===")
message(STATUS "RAWRXD_GRAPH_SOURCES_REFERENCED=${_SG_DECLARED}")
message(STATUS "RAWRXD_GRAPH_SOURCES_PRESENT=${_SG_PRESENT}")
message(STATUS "RAWRXD_GRAPH_SOURCES_ABSENT=${_SG_ABSENT}")
message(STATUS "RAWRXD_GRAPH_COMMENTED_SOURCE_REFS=${_SG_NCOMMENTED}")
message(STATUS "RAWRXD_GRAPH_ABSENT_BY_AREA=${_SG_AREA}")
message(STATUS "RAWRXD_GRAPH_RESTORED_EMPTY_UNITS=${_SG_RESTORED}")
message(STATUS "NOTE=GRAPH_RESTORED_EMPTY_UNITS exist but contain no")
message(STATUS "  implementation and export no symbol; NOT a functional PASS")
message(STATUS "NOTE=This census is INFORMATIONAL only; ABSENT > 0 does not")
message(STATUS "  fail configure. Use RAWRXD_STRICT_SOURCES=ON to make absent")
message(STATUS "  sources fatal, or implement them to reduce this count.")
message(STATUS "=== /RAWRXD_GRAPH_CENSUS_001 ===")
message(STATUS "")

# --- machine-readable twin --------------------------------------------------
# Same numbers as one record per declared path, so the census is diffable
# between commits instead of re-derivable only from prose.
set(_SG_TSV "${CMAKE_SOURCE_DIR}/audit/RAWRXD_BUILD_GRAPH_CENSUS_001.tsv")
get_filename_component(_SG_TSV_DIR "${_SG_TSV}" DIRECTORY)
file(MAKE_DIRECTORY "${_SG_TSV_DIR}")
string(REPLACE ";" "\n" _SG_ROWS_TEXT "${_SG_ROWS}")
file(WRITE "${_SG_TSV}"
     "PATH\tAREA\tEXISTS\tDISPOSITION\n${_SG_ROWS_TEXT}\n")
message(STATUS "RAWRXD_GRAPH_CENSUS_TSV=${_SG_TSV}")
