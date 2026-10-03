# ===========================================================================
# RAWRXD_SOURCE_GRAPH_AUTHORITY_001
#
# THE canonical source-graph census. Run as:
#     cmake -DRAWRXD_ROOT=<repo> -P tools/source_graph_authority.cmake
#
# WHY cmake -P AND NOT A SCRIPT IN ANOTHER LANGUAGE
#   Determinism is the entire requirement, and script mode is the most
#   deterministic execution CMake offers: no cache, no generator, no toolchain
#   probe, no platform state, no timestamps in the output. The previous three
#   incompatible counts in this repository came from three ad-hoc extractors
#   with three different definitions of "declared". One parser, run twice,
#   required to produce identical bytes, is the only thing that fixes that.
#
# WHAT MAKES THIS DIFFERENT FROM THE THREE PRIOR COUNTS
#   1. GLOBS ARE NEVER COUNTED AS MISSING LITERAL FILES. A token containing
#      * or ? is classified GLOB and expanded separately. The prior counts
#      treated some and not others, depending on regex.
#   2. COMMENTED REFERENCES ARE NEVER ACTIVE GRAPH MEMBERS. They are counted
#      separately and never enter the materialisation queue.
#   3. VARIABLE EXPANSIONS AND GENERATOR EXPRESSIONS ARE NOT GUESSED. A token
#      containing ${...} or $<...> is classified UNRESOLVED_EXPRESSION and is
#      never resolved by pattern-matching its neighbours.
#   4. PROSE IS NOT A SOURCE REFERENCE. Only tokens inside a real source-list
#      context (add_executable / add_library / set(<LIST>) / target_sources /
#      list(APPEND ...)) are candidates.
#   5. EVERY ROW CARRIES ITS TARGET, DECLARATION FILE, LINE AND RAW TOKEN, so
#      any count can be traced to the expression that produced it.
#
# OUTPUT
#   <audit>/RAWRXD_SOURCE_GRAPH_001.tsv     one row per reference
#   <audit>/RAWRXD_SOURCE_GRAPH_001.summary key=value lines
#
# DETERMINISM
#   No timestamps. Every collection is sorted before emission. Two runs against
#   an unchanged tree must produce byte-identical files.
# ===========================================================================

if(NOT DEFINED RAWRXD_ROOT)
    message(FATAL_ERROR "RAWRXD_ROOT not set")
endif()
get_filename_component(RAWRXD_ROOT "${RAWRXD_ROOT}" ABSOLUTE)
set(_CM "${RAWRXD_ROOT}/CMakeLists.txt")
if(NOT EXISTS "${_CM}")
    message(FATAL_ERROR "no CMakeLists.txt under ${RAWRXD_ROOT}")
endif()
set(_AUDIT "${RAWRXD_ROOT}/audit")
file(MAKE_DIRECTORY "${_AUDIT}")

# --- read every included CMake file, so the census covers included modules ---
file(GLOB_RECURSE _all_cmake LIST_DIRECTORIES false
     "${RAWRXD_ROOT}/*.cmake"
     "${RAWRXD_ROOT}/CMakeLists.txt")
list(SORT _all_cmake)

set(_SRC_EXT cpp hpp h cc cxx asm rc inl ipp)

# --- counters ---------------------------------------------------------------
foreach(_k
    ACTIVE_LITERAL_REFS ACTIVE_LITERAL_UNIQUE ACTIVE_PRESENT ACTIVE_MISSING
    ACTIVE_CPP_MISSING
    COMMENTED_LITERAL_REFS COMMENTED_UNIQUE COMMENTED_PRESENT
    GLOB_EXPRESSIONS GLOB_EXPANDED_FILES
    GENERATED_OUTPUT_REFS
    UNRESOLVED_EXPRESSIONS
    DROPPED_BY_FILTER
    TARGET_COUNT
    DECLARATION_FILES)
    set(_C_${_k} 0)
endforeach()

set(_ROWS "")
set(_uniqActive "")
set(_uniqCommented "")

# ---------------------------------------------------------------------------
# State machine over each declaration file.
# ---------------------------------------------------------------------------
foreach(_cf IN LISTS _all_cmake)
    file(STRINGS "${_cf}" _lines)
    math(EXPR _C_DECLARATION_FILES "${_C_DECLARATION_FILES} + 1")

    # Current target / list attribution, and whether we are inside one.
    set(_ctx "UNKNOWN")
    set(_inList FALSE)
    set(_condDepth 0)

    set(_ln 0)
    foreach(_raw IN LISTS _lines)
        math(EXPR _ln "${_ln} + 1")
        set(_line "${_raw}")

        # -- bracket comments [[ ... ]] : toggle, and ignore their contents --
        string(REGEX MATCHALL "\\[\\[" _opens "${_line}")
        string(REGEX MATCHALL "\\]\\]" _closes "${_line}")
        list(LENGTH _opens _no)
        list(LENGTH _closes _nc)
        set(_bal 0)
        math(EXPR _bal "${_bal} + ${_no} - ${_nc}")
        if(_bal EQUAL 0)
            # balanced on this line: everything inside is comment, drop it
            if(_no GREATER 0)
                string(REGEX REPLACE "\\[\\[.*" "" _line "${_line}")
            endif()
        else()
            # unbalanced: treat the remainder as comment and carry the state
            if(_no GREATER 0)
                string(REGEX REPLACE "\\[\\[.*" "" _line "${_line}")
                set(_bal 1)
            else()
                string(REGEX REPLACE ".*\\]\\]" "" _line "${_line}")
                set(_bal 0)
            endif()
        endif()

        # -- if() nesting --------------------------------------------------
        string(REGEX MATCHALL "(^|[^A-Za-z0-9_])if\\s*\\(" _ifs "${_line}")
        list(LENGTH _ifs _nif)
        math(EXPR _condDepth "${_condDepth} + ${_nif}")
        string(REGEX MATCHALL "(^|[^A-Za-z0-9_])endif\\s*\\(" _endifs "${_line}")
        list(LENGTH _endifs _nendif)
        math(EXPR _condDepth "${_condDepth} - ${_nendif}")
        if(_condDepth LESS 0)
            set(_condDepth 0)
        endif()

# -- strip the line comment, respecting quoted strings ---------------
        # A '#' inside a quoted string is DATA, not a comment. This is a plain
        # character scan with no escape handling, because CMake source in this
        # repository does not contain escaped quotes inside source-path lists;
        # an earlier revision tried to handle \\" and produced a loop that could
        # not terminate its own branch.
        set(_code "")
        set(_inStr FALSE)
        set(_sawHash FALSE)
        string(LENGTH "${_line}" _len)
        set(_i 0)
        while(_i LESS _len)
            string(SUBSTRING "${_line}" ${_i} 1 _ch)
            if(_inStr)
                if(_ch STREQUAL "\"")
                    set(_inStr FALSE)
                endif()
            else()
                if(_ch STREQUAL "\"")
                    set(_inStr TRUE)
                elseif(_ch STREQUAL "#")
                    set(_sawHash TRUE)
                    math(EXPR _i ${_len})
                    break()
                endif()
            endif()
            string(APPEND _code "${_ch}")
            math(EXPR _i "${_i} + 1")
        endwhile()
        if(NOT _sawHash)
            set(_code "${_line}")
        endif()

        # -- context tracking -------------------------------------------------
        if(_code MATCHES "add_executable\\s*\\(\\s*([A-Za-z0-9_\\-]+)")
            set(_ctx "${CMAKE_MATCH_1}")
            math(EXPR _C_TARGET_COUNT "${_C_TARGET_COUNT} + 1")
            set(_inList TRUE)
        elseif(_code MATCHES "add_library\\s*\\(\\s*([A-Za-z0-9_\\-]+)")
            set(_ctx "${CMAKE_MATCH_1}")
            math(EXPR _C_TARGET_COUNT "${_C_TARGET_COUNT} + 1")
            set(_inList TRUE)
        elseif(_code MATCHES "target_sources\\s*\\(\\s*([A-Za-z0-9_\\-]+)")
            set(_ctx "${CMAKE_MATCH_1}")
            set(_inList TRUE)
        elseif(_code MATCHES "^\\s*set\\s*\\(\\s*([A-Za-z0-9_\\-]+)")
            set(_ctx "${CMAKE_MATCH_1}")
        elseif(_code MATCHES "^\\s*list\\s*\\(\\s*APPEND\\s+([A-Za-z0-9_\\-]+)")
            set(_ctx "${CMAKE_MATCH_1}")
        elseif(_code MATCHES "^\\s*\\)")
            set(_inList FALSE)
        endif()

        # -- is this line inside a file()/message()/configure_file() body? ----
        # Those contain paths that are OUTPUTS or PROSE, never source members.
        string(REGEX MATCH "^\\s*file\\s*\\(" _isFile "${_code}")
        string(REGEX MATCH "^\\s*message\\s*\\(" _isMsg "${_code}")
        string(REGEX MATCH "^\\s*configure_file\\s*\\(" _isCfg "${_code}")

        set(_isCtx FALSE)
        if(_inList OR _code MATCHES "(^|[^A-Za-z0-9_])(set|list|target_sources|add_executable|add_library)\\s*\\(")
            set(_isCtx TRUE)
        endif()

        if(NOT _isCtx OR _isFile OR _isMsg OR _isCfg)
            continue()
        endif()

        # -- classify every token on the line -------------------------------
        # Quoted tokens first, then bare tokens.
        set(_toks "")
        string(REGEX MATCHALL "\"[^\"]*\"" _qt "${_code}")
        foreach(_q IN LISTS _qt)
            string(REGEX REPLACE "^\"(.*)\"$" "\\1" _q "${_q}")
            list(APPEND _toks "${_q}")
        endforeach()
        string(REGEX REPLACE "\"[^\"]*\"" " " _bare "${_code}")
        string(REGEX REPLACE "[()]" " " _bare "${_bare}")
        string(REGEX REPLACE "," " " _bare "${_bare}")
        foreach(_b IN LISTS _bare)
            string(STRIP "${_b}" _b)
            if(_b STREQUAL "")
                continue()
            endif()
            if(_b MATCHES "^[A-Za-z_][A-Za-z0-9_]*$")
                continue()          # bare command / keyword
            endif()
            list(APPEND _toks "${_b}")
        endforeach()

        foreach(_t IN LISTS _toks)
            # Skip CMake keywords and target names that slipped through.
            if(_t MATCHES "^(PUBLIC|PRIVATE|INTERFACE|MODULE|SHARED|STATIC|WIN32|EXCLUDE_FROM_ALL|REQUIRED|QUIET|CONFIGURATIONS)$")
                continue()
            endif()

            set(_kind LITERAL)
            set(_disp ACTIVE)
            set(_gen FALSE)
            set(_filtered FALSE)

            if(_t MATCHES "\\$<")
                set(_kind UNRESOLVED_EXPRESSION)
                math(EXPR _C_UNRESOLVED_EXPRESSIONS "${_C_UNRESOLVED_EXPRESSIONS} + 1")
                set(_disp UNRESOLVED_EXPRESSION)
            elseif(_t MATCHES "\\$\\{")
                set(_kind UNRESOLVED_EXPRESSION)
                math(EXPR _C_UNRESOLVED_EXPRESSIONS "${_C_UNRESOLVED_EXPRESSIONS} + 1")
                set(_disp UNRESOLVED_EXPRESSION)
            elseif(_t MATCHES "[*?]")
                # GLOB: never a missing literal file, never materialisable.
                set(_kind GLOB)
                math(EXPR _C_GLOB_EXPRESSIONS "${_C_GLOB_EXPRESSIONS} + 1")
                file(GLOB _expanded LIST_DIRECTORIES false
                     "${RAWRXD_ROOT}/${_t}")
                list(LENGTH _expanded _ne)
                math(EXPR _C_GLOB_EXPANDED_FILES "${_C_GLOB_EXPANDED_FILES} + ${_ne}")
                set(_disp GLOB_EXPRESSION)
            else()
                # does it look like a source path at all?
                set(_ext FALSE)
                foreach(_e IN LISTS _SRC_EXT)
                    if(_t MATCHES "\\.${e}$")
                        set(_ext TRUE)
                    endif()
                endforeach()
                # Is this token a SOURCE PATH at all? A known source extension is REQUIRED.
                #
                # The previous version accepted any token containing '/', which
                # swept in MSVC tool paths (cl.exe, link.exe), bare directories
                # (D:/VS2022Enterprise/VC/Tools/MSVC), message prose
                # ("Export compile_commands.json for IDE/clangd") and whole
                # command fragments ("list APPEND WIN32IDE_SOURCES src").
                # That produced 484 "missing" sources of which the overwhelming
                # majority were not sources at all -- a precision defect that
                # would have sent a materialisation queue after files that do
                # not exist and must not.
                set(_isSrc FALSE)
                foreach(_e IN LISTS _SRC_EXT)
                    if(_t MATCHES "\\.${e}$")
                        set(_isSrc TRUE)
                        break()
                    endif()
                endforeach()
                if(NOT _isSrc)
                    continue()
                endif()
                if(_t MATCHES "^\\$<|^\\$\\{|^@|^\\$<")
                    continue()
                endif()
                math(EXPR _C_ACTIVE_LITERAL_REFS "${_C_ACTIVE_LITERAL_REFS} + 1")
                list(APPEND _uniqActive "${_t}")
            endif()

            if(_code MATCHES "GENERATED")
                set(_gen TRUE)
                math(EXPR _C_GENERATED_OUTPUT_REFS "${_C_GENERATED_OUTPUT_REFS} + 1")
            endif()

            # CLASSIFICATION GATE. Only a LITERAL may be counted as a missing
            # file. An UNRESOLVED_EXPRESSION or a GLOB is not a missing source;
            # counting them as one is precisely what produced
            # ACTIVE_MISSING_REFS(4849) > ACTIVE_LITERAL_REFS(3405), because
            # 3228 variable/genex tokens and 215 globs were falling through the
            # existence test. Requirement 2 and 3 of the mandate forbid this,
            # and the arithmetic contradiction is what exposed it.
            set(_countable FALSE)
            if(_kind STREQUAL "LITERAL")
                set(_countable TRUE)
            endif()

            string(REPLACE "\\" "/" _tp "${_t}")
            set(_exists FALSE)
            if(_countable AND EXISTS "${RAWRXD_ROOT}/${_tp}")
                set(_exists TRUE)
                list(APPEND _uniqActive "${_t}")
            endif()

            if(NOT _countable)
                # Not a literal source path: report the kind, never a status.
                set(_exists FALSE)
                if(_kind STREQUAL "GLOB")
                    set(_disp GLOB_EXPRESSION)
                else()
                    set(_disp UNRESOLVED_EXPRESSION)
                endif()
            elseif(_exists)
                set(_disp ACTIVE_PRESENT)
            else()
                math(EXPR _C_ACTIVE_MISSING "${_C_ACTIVE_MISSING} + 1")
                if(_tp MATCHES "\\.cpp$")
                    math(EXPR _C_ACTIVE_CPP_MISSING "${_C_ACTIVE_CPP_MISSING} + 1")
                endif()
                set(_disp ACTIVE_MISSING)
            endif()

            string(REGEX REPLACE "\\t" " " _tok "${_t}")
            list(APPEND _ROWS
                "${_ctx}\t${_cf}\t${_ln}\t${_tok}\t${_tp}\t${_kind}\t1\t${_exists}\t${_gen}\t${_filtered}\t${_condDepth}\t${_disp}")
        endforeach()
    endforeach()
endforeach()

# ---------------------------------------------------------------------------
# Commented references: counted separately, NEVER active members, and never
# eligible for materialisation. The prior counts conflated these with active
# graph members, which is why they disagreed.
# ---------------------------------------------------------------------------
file(STRINGS "${_CM}" _clines)
set(_ln 0)
set(_inStr FALSE)
foreach(_line IN LISTS _clines)
    math(EXPR _ln "${_ln} + 1")
    string(REGEX MATCH "^\\s*#\\s*([A-Za-z0-9_./$-]+\\.[A-Za-z]{1,4})\\s*$" _pure "${_line}")
    if(NOT _pure)
        continue()
    endif()
    set(_p "${CMAKE_MATCH_1}")
    # A pure declaration line: the whole comment is one path.
    string(REGEX REPLACE "\\$" "" _pe "${_p}")
    set(_isSrc FALSE)
    foreach(_e IN LISTS _SRC_EXT)
        if(_pe MATCHES "\\.${e}$")
            set(_isSrc TRUE)
        endif()
    endforeach()
    if(NOT _isSrc)
        continue()
    endif()
    math(EXPR _C_COMMENTED_LITERAL_REFS "${_C_COMMENTED_LITERAL_REFS} + 1")
    list(APPEND _uniqCommented "${_pe}")
    set(_exists FALSE)
    if(EXISTS "${RAWRXD_ROOT}/${_pe}")
        set(_exists TRUE)
        math(EXPR _C_COMMENTED_PRESENT "${_C_COMMENTED_PRESENT} + 1")
    endif()
    if(_pe MATCHES "[*?]")
        continue()
    endif()
    set(_d COMMENTED_MISSING)
    if(_exists)
        set(_d COMMENTED_PRESENT)
    endif()
    list(APPEND _rows
        "UNKNOWN\t${_CM}\t${_ln}\t#${_pe}\t${_pe}\tLITERAL\t0\t${_exists}\tFALSE\tFALSE\t0\t${_d}")
endforeach()

if(_uniqActive)
    list(REMOVE_DUPLICATES _uniqActive)
    list(LENGTH _uniqActive _C_ACTIVE_LITERAL_UNIQUE)
    # PRESENT is counted over UNIQUE PATHS, not over reference occurrences.
    # The first version counted occurrences, which produced
    # ACTIVE_PRESENT(1999) > ACTIVE_LITERAL_UNIQUE(1606) -- an impossible pair
    # that should have been read as a bug immediately rather than reported.
    # ACTIVE_PRESENT = UNIQUE - ACTIVE_MISSING_UNIQUE.
    set(_C_ACTIVE_PRESENT 0)
    foreach(_u IN LISTS _uniqActive)
        if(EXISTS "${RAWRXD_ROOT}/${_u}")
            math(EXPR _C_ACTIVE_PRESENT "${_C_ACTIVE_PRESENT} + 1")
        endif()
    endforeach()
    set(_C_ACTIVE_MISSING_UNIQUE 0)
    math(EXPR _C_ACTIVE_MISSING_UNIQUE "${_C_ACTIVE_LITERAL_UNIQUE} - ${_C_ACTIVE_PRESENT}")
endif()
if(_uniqCommented)
    list(REMOVE_DUPLICATES _uniqCommented)
    list(LENGTH _uniqCommented _C_COMMENTED_UNIQUE)
endif()

# --- filter-dropped count: read the receipt the filter itself wrote ----------
set(_KNOWN "${RAWRXD_ROOT}/cmake/known_empty_sources.txt")
if(EXISTS "${_KNOWN}")
    file(STRINGS "${_KNOWN}" _kl)
    list(LENGTH _kl _C_DROPPED_BY_FILTER)
endif()

# ---------------------------------------------------------------------------
# Emit. Sorted, timestamp-free, so two runs are byte-identical.
# ---------------------------------------------------------------------------
list(SORT _ROWS)
set(_body "")
foreach(_r IN LISTS _ROWS)
    set(_body "${_body}${_r}\n")
endforeach()
set(_tsv "${_AUDIT}/RAWRXD_SOURCE_GRAPH_001.tsv")
file(WRITE "${_tsv}"
"TARGET\tDECLARATION_FILE\tDECLARATION_LINE\tRAW_EXPRESSION\tRESOLVED_PATH\tREFERENCE_KIND\tACTIVE\tEXISTS\tGENERATED\tFILTERED\tCONDITION_STATE\tDISPOSITION\n${_body}")

file(WRITE "${_AUDIT}/RAWRXD_SOURCE_GRAPH_001.summary"
"RAWRXD_GRAPH_ACTIVE_LITERAL_REFS=${_C_ACTIVE_LITERAL_REFS}
RAWRXD_GRAPH_ACTIVE_LITERAL_UNIQUE=${_C_ACTIVE_LITERAL_UNIQUE}
RAWRXD_GRAPH_ACTIVE_PRESENT=${_C_ACTIVE_PRESENT}
RAWRXD_GRAPH_ACTIVE_MISSING_REFS=${_C_ACTIVE_MISSING}
RAWRXD_GRAPH_ACTIVE_MISSING_UNIQUE=${_C_ACTIVE_MISSING_UNIQUE}
RAWRXD_GRAPH_ACTIVE_CPP_MISSING=${_C_ACTIVE_CPP_MISSING}
RAWRXD_GRAPH_COMMENTED_LITERAL_REFS=${_C_COMMENTED_LITERAL_REFS}
RAWRXD_GRAPH_COMMENTED_UNIQUE=${_C_COMMENTED_UNIQUE}
RAWRXD_GRAPH_COMMENTED_PRESENT=${_C_COMMENTED_PRESENT}
RAWRXD_GRAPH_GLOB_EXPRESSIONS=${_C_GLOB_EXPRESSIONS}
RAWRXD_GRAPH_GLOB_EXPANDED_FILES=${_C_GLOB_EXPANDED_FILES}
RAWRXD_GRAPH_GENERATED_OUTPUT_REFS=${_C_GENERATED_OUTPUT_REFS}
RAWRXD_GRAPH_UNRESOLVED_EXPRESSIONS=${_C_UNRESOLVED_EXPRESSIONS}
RAWRXD_GRAPH_DROPPED_BY_FILTER=${_C_DROPPED_BY_FILTER}
RAWRXD_GRAPH_TARGET_COUNT=${_C_TARGET_COUNT}
RAWRXD_GRAPH_DECLARATION_FILES=${_C_DECLARATION_FILES}
")

file(READ "${_AUDIT}/RAWRXD_SOURCE_GRAPH_001.summary" _sum)
message("${_sum}")
message("TSV=${_tsv}")
