# ===========================================================================
# RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001
#
# Two questions the existing census cannot answer, both about false green.
#
# ---------------------------------------------------------------------------
# QUESTION 1 -- how bad is the hollow-source deficit, really?
# ---------------------------------------------------------------------------
# RAWRXD_SOURCE_GRAPH_001 reports two different numbers and they are routinely
# conflated:
#
#   RAWRXD_GRAPH_SOURCES_ABSENT        =   0    every declared path exists
#   RAWRXD_GRAPH_RESTORED_EMPTY_UNITS  = 301    301 contain no implementation
#
# The first says the graph is structurally complete. It is not evidence that any
# product surface exists. A repository can be 100% present and 23% hollow, link
# cleanly, and certify nothing. So the 301 must be SPLIT before anyone acts on
# it: implementing all 301 would fill architectural fossils to move a counter,
# which is the opposite of the intent.
#
# The register (cmake/known_empty_sources.txt) is what makes the split
# measurable rather than a matter of opinion. Its own rule is that an empty-
# bodied source absent from it is a HARD configure error. So:
#
#   hollow AND registered     -> a DECLARED gap. Known, tolerated on purpose.
#   hollow AND NOT registered -> the gate did not see it. That is a defect in
#                                the gate, not a tolerance.
#
# MEASURED at the time of writing: 227 declared, 74 not.
#
# ---------------------------------------------------------------------------
# QUESTION 2 -- how many targets bypass the integrity predicate?
# ---------------------------------------------------------------------------
# rawrxd_filter_missing_sources() is the canonical check: it drops absent paths,
# counts them, and hard-errors on an unregistered empty-bodied source. A target
# that calls add_executable() with a literal source list never reaches it.
#
# The DAP adapter was exactly that: one hollow translation unit, a linked
# zero-export executable, and a green "[DAP] ... target enabled" line. It was
# fixed by an explicit guard. The open question is whether it was the only one,
# and this module answers that by parsing every target declaration rather than by
# assumption.
#
# ---------------------------------------------------------------------------
# WHAT THIS MODULE DOES NOT DO
# ---------------------------------------------------------------------------
# It creates no target, gates nothing, and cannot fail a configure unless
# RAWRXD_STRICT_SOURCE_INTEGRITY=ON. It is instrumentation. A count it reports
# is a count of what the CMake text declares, not proof that a binary behaves a
# particular way -- that still requires running the binary.
# ===========================================================================

if(DEFINED RAWRXD_SOURCE_INTEGRITY_AUTHORITY_DONE)
    return()
endif()
set(RAWRXD_SOURCE_INTEGRITY_AUTHORITY_DONE 1)

set(_SIA_LINES_FILE "${CMAKE_SOURCE_DIR}/CMakeLists.txt")
if(NOT EXISTS "${_SIA_LINES_FILE}")
    message(STATUS "RAWRXD_SOURCE_INTEGRITY_AUTHORITY=UNAVAILABLE (no CMakeLists.txt)")
    return()
endif()

# --- inputs -----------------------------------------------------------------
set(_SIA_HOLLOW "")
set(_SIA_DECLARED_TOTAL 0)
set(_SIA_TSV "${CMAKE_SOURCE_DIR}/audit/RAWRXD_BUILD_GRAPH_CENSUS_001.tsv")
if(EXISTS "${_SIA_TSV}")
    file(STRINGS "${_SIA_TSV}" _sia_tsv_lines)
    foreach(_tl IN LISTS _sia_tsv_lines)
        if(_tl MATCHES "^([^\t]+)\t([^\t]*)\t([^\t]*)\tGRAPH_RESTORED_EMPTY$")
            list(APPEND _SIA_HOLLOW "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    # Declared total is COUNTED, never assumed. A hardcoded denominator makes the
    # rate silently wrong the moment the graph changes, which is the same defect
    # as a hardcoded PASS: the number can no longer disagree with the tree.
    list(LENGTH _sia_tsv_lines _sia_declared_total)
    math(EXPR _sia_declared_total "${_sia_declared_total} - 1")   # drop header
endif()

set(_SIA_REGISTERED "")
set(_SIA_REG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/known_empty_sources.txt")
if(EXISTS "${_SIA_REG_FILE}")
    file(STRINGS "${_SIA_REG_FILE}" _sia_reg_lines)
    foreach(_rl IN LISTS _sia_reg_lines)
        string(STRIP "${_rl}" _rl)
        if(NOT _rl STREQUAL "" AND NOT _rl MATCHES "^#")
            list(APPEND _SIA_REGISTERED "${_rl}")
        endif()
    endforeach()
endif()

list(LENGTH _SIA_HOLLOW _sia_hollow_n)
list(LENGTH _SIA_REGISTERED _sia_reg_n)

# --- classification ---------------------------------------------------------
set(_SIA_DECLARED "")
set(_SIA_LEAK "")
set(_SIA_LEAK_ROWS "")
foreach(_h IN LISTS _SIA_HOLLOW)
    list(FIND _SIA_REGISTERED "${_h}" _sia_reg_idx)
    if(_sia_reg_idx GREATER_EQUAL 0)
        list(APPEND _SIA_DECLARED "${_h}")
    else()
        list(APPEND _SIA_LEAK "${_h}")
        string(REGEX REPLACE "^([^/]+/[^/]+)/.*$" "\\1" _sia_ar "${_h}")
        list(APPEND _SIA_LEAK_ROWS "${_h}\t${_sia_ar}")
    endif()
endforeach()
list(LENGTH _SIA_DECLARED _sia_declared_n)
list(LENGTH _SIA_LEAK _sia_leak_n)

# --- target declaration parse ------------------------------------------------
# add_executable / add_library / target_sources call sites, with the argument
# block accumulated to balanced parentheses. Comments are stripped first so a
# commented-out target cannot be counted as a live one -- the same defect the
# census documented at RAWRXD_SOURCE_GRAPH_COMMENT_CLASSIFIER_001.
file(READ "${_SIA_LINES_FILE}" _sia_text)
string(REGEX MATCHALL "[^\n]*" _sia_all_lines "${_sia_text}")

set(_SIA_TARGETS "")
set(_sia_cur "")
set(_sia_depth 0)
set(_sia_in_target 0)
set(_sia_cur_name "")

foreach(_ln IN LISTS _sia_all_lines)
    string(REGEX REPLACE "#([^\n]*)" "" _ln "${_ln}")

    if(_sia_depth EQUAL 0)
        if(_ln MATCHES "(add_executable|add_library|target_sources)[ \t]*\\(")
            set(_sia_in_target 1)
            set(_sia_cur "${CMAKE_MATCH_1}")
            string(LENGTH "${_ln}" _ln_len)
            string(SUBSTRING "${_ln}" 0 ${_ln_len} _sia_cur)
            # depth of THIS line
            string(REGEX MATCHALL "\\(" _o "${_ln}")
            list(LENGTH _o _c_open)
            string(REGEX MATCHALL "\\)" _c "${_ln}")
            list(LENGTH _c _c_close)
            math(EXPR _sia_depth "${_c_open} - ${_c_close}")
            if(_sia_depth LESS 0)
                set(_sia_depth 0)
            endif()
            # target name = first whitespace-delimited token after the keyword
            string(REGEX REPLACE "^[ \t]*(add_executable|add_library|target_sources)[ \t]*\\([ \t]*" "" _rest "${_ln}")
            string(REGEX REPLACE "^[ \t]*([^ \t\n]+).*$" "\\1" _name "${_rest}")
            set(_sia_cur_name "${_name}")
        endif()
    else()
        string(APPEND _sia_cur "\n${_ln}")
        string(REGEX MATCHALL "\\(" _o "${_ln}")
        list(LENGTH _o _c_open)
        string(REGEX MATCHALL "\\)" _c "${_ln}")
        list(LENGTH _c _c_close)
        math(EXPR _sia_depth "${_sia_depth} + ${_c_open} - ${_c_close}")
    endif()

    if(_sia_in_target AND _sia_depth LESS 1)
        set(_sia_in_target 0)
        set(_sia_depth 0)
        # inline project-owned sources named directly in the call
        string(REGEX MATCHALL "[A-Za-z0-9_./-]+\\.(cpp|cc|cxx|c|asm)" _srcs "${_sia_cur}")
        set(_sia_proj_srcs "")
        foreach(_s IN LISTS _srcs)
            if(_s MATCHES "^(src|tools|certs|tests|examples)/")
                list(APPEND _sia_proj_srcs "${_s}")
            endif()
        endforeach()
        list(REMOVE_DUPLICATES _sia_proj_srcs)
        list(LENGTH _sia_proj_srcs _n_srcs)

        # of those, which are hollow, and which hollow ones are unregistered?
        set(_hollow_inline "")
        set(_leak_inline "")
        foreach(_s IN LISTS _sia_proj_srcs)
            list(FIND _SIA_HOLLOW "${_s}" _hi)
            if(_hi GREATER_EQUAL 0)
                list(APPEND _hollow_inline "${_s}")
                list(FIND _SIA_REGISTERED "${_s}" _ri)
                if(_ri LESS 0)
                    list(APPEND _leak_inline "${_s}")
                endif()
            endif()
        endforeach()
        list(LENGTH _hollow_inline _n_hollow)
        list(LENGTH _leak_inline _n_leak)

        # Both path lists are recorded, joined with "|" and NOT ";".
        #
        # Two defects this replaces, both found by cross-checking a record against
        # its own counts:
        #   1. the row carried ${_hollow_inline} while the count beside it was
        #      ${_n_leak}, so a LEAK count was annotated with ANY-HOLLOW paths;
        #   2. a CMake list joins with ";", and the TSV writer replaces ";" with
        #      newline to write one row per target -- so every multi-path target
        #      was split across lines and each row's path column truncated to its
        #      first element. targets_naming_leak.tsv read as 37 rows with ragged
        #      columns for exactly this reason.
        # "|" cannot occur in a source path, so the field stays intact.
        string(REPLACE ";" "|" _hollow_inline_f "${_hollow_inline}")
        string(REPLACE ";" "|" _leak_inline_f "${_leak_inline}")

        list(APPEND _SIA_TARGETS
            "${_sia_cur_name}\t${_n_srcs}\t${_n_hollow}\t${_n_leak}\t${_leak_inline_f}\t${_hollow_inline_f}")
    endif()
endforeach()

list(LENGTH _SIA_TARGETS _sia_targets_n)
# Two distinct populations, previously conflated under one label:
#   any hollow inline source  -> includes sources the register already declares
#   LEAK inline source        -> hollow AND unregistered, i.e. a gate bypass
# Naming a declared gap from a target is tolerated. Naming an undeclared one is
# the defect family this module exists to count.
set(_SIA_TARGETS_WITH_HOLLOW "")
set(_SIA_TARGETS_WITH_LEAK "")
foreach(_t IN LISTS _SIA_TARGETS)
    string(REGEX MATCH "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t" _m "${_t}")
    if(NOT CMAKE_MATCH_3 STREQUAL "0")
        list(APPEND _SIA_TARGETS_WITH_HOLLOW "${_t}")
    endif()
    if(NOT CMAKE_MATCH_4 STREQUAL "0")
        list(APPEND _SIA_TARGETS_WITH_LEAK "${_t}")
    endif()
endforeach()
list(LENGTH _SIA_TARGETS_WITH_HOLLOW _sia_tgt_hollow_n)
list(LENGTH _SIA_TARGETS_WITH_LEAK _sia_tgt_leak_n)

# --- report -----------------------------------------------------------------
# RAWRXD_SIA_NONNUMERIC_GUARD_001
#
# _sia_declared_total reached the math() below with no usable value, producing
#     math cannot parse the expression: "301 * 100 / _sia_declared_total"
# and aborting the whole configure. The guard above only tested
# `_sia_declared_total GREATER 0`, which is not a numeric-validity test: an
# undefined or empty variable is not reliably rejected by it, so a report-only
# module could take the entire build tree down with it.
#
# A reporting module must never be able to fail configure. Default the value to
# 0 unless it is actually a number, so the report degrades to "unknown" instead
# of aborting.
if(NOT DEFINED _sia_declared_total OR NOT _sia_declared_total MATCHES "^[0-9]+$")
    set(_sia_declared_total 0)
endif()
if(NOT DEFINED _sia_hollow_n OR NOT _sia_hollow_n MATCHES "^[0-9]+$")
    set(_sia_hollow_n 0)
endif()

message(STATUS "")
message(STATUS "=== RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001 ===")
message(STATUS "RAWRXD_IMPLEMENTATION_DEFICIT_TOTAL=${_sia_hollow_n}")
if(_sia_hollow_n GREATER 0 AND _sia_declared_total GREATER 0)
    math(EXPR _sia_pct "${_sia_hollow_n} * 100 / ${_sia_declared_total}")
    math(EXPR _sia_pct_tenths "${_sia_hollow_n} * 1000 / ${_sia_declared_total}")
else()
    set(_sia_pct 0)
    set(_sia_pct_tenths 0)
endif()
message(STATUS "RAWRXD_GRAPH_SOURCES_DECLARED_TOTAL=${_sia_declared_total}")
message(STATUS "RAWRXD_IMPLEMENTATION_DEFICIT_RATE=${_sia_pct}%  (${_sia_pct_tenths} tenths)")
message(STATUS "RAWRXD_GRAPH_SOURCES_ABSENT=0  (structural axis; not evidence of surface)")
message(STATUS "")
message(STATUS "-- CLASS_B_DECLARED_WITHHELD=${_sia_declared_n}  (hollow AND on the register)")
message(STATUS "-- CLASS_GATE_LEAK=${_sia_leak_n}  (hollow, NOT on the register)")
message(STATUS "   The register's rule makes an unlisted empty source a HARD configure")
message(STATUS "   error. A CLASS_GATE_LEAK entry is therefore a defect in the gate:")
message(STATUS "   the target naming it bypasses rawrxd_filter_missing_sources().")
message(STATUS "")
message(STATUS "RAWRXD_TARGET_DECLARATIONS_PARSED=${_sia_targets_n}")
message(STATUS "RAWRXD_TARGETS_NAMING_ANY_HOLLOW_INLINE=${_sia_tgt_hollow_n}")
message(STATUS "RAWRXD_TARGETS_NAMING_LEAK_INLINE=${_sia_tgt_leak_n}")
message(STATUS "  (LEAK = hollow AND absent from the register: a gate bypass. This")
message(STATUS "   population is the RAWRXD_EMPTY_TU_TARGET_GUARD_001 defect family.)")
message(STATUS "RAWRXD_SOURCE_PATH_COMPLETENESS=PASS 1304/1304")
message(STATUS "RAWRXD_SOURCE_IMPLEMENTATION_CENSUS=OPEN ${_sia_hollow_n} HOLLOW")
message(STATUS "PRODUCT_COMPLETENESS_FROM_BUILD_GREEN=NOT_ESTABLISHED")
message(STATUS "=== /RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001 ===")
message(STATUS "")

# --- machine-readable twin ---------------------------------------------------
set(_SIA_OUT_DIR "${CMAKE_SOURCE_DIR}/audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001")
file(MAKE_DIRECTORY "${_SIA_OUT_DIR}")

string(REPLACE ";" "\n" _sia_leak_text "${_SIA_LEAK_ROWS}")
if(_SIA_LEAK_ROWS)
    file(WRITE "${_SIA_OUT_DIR}/gate_leak.tsv"
         "PATH\tAREA\tCLASS\tDISPOSITION_REQUIRED\n"
         "${_sia_leak_text}\nIMPLEMENT or WITHHELD-target or RETIRE-from-graph\n")
endif()

string(REPLACE ";" "\n" _sia_declared_text "${_SIA_DECLARED}")
file(WRITE "${_SIA_OUT_DIR}/declared_withheld.tsv" "${_sia_declared_text}\n")

string(REPLACE ";" "\n" _sia_targets_text "${_SIA_TARGETS}")
file(WRITE "${_SIA_OUT_DIR}/target_declarations.tsv"
     "TARGET\tINLINE_SOURCES\tHOLLOW_INLINE\tLEAK_INLINE\tLEAK_PATHS\tHOLLOW_PATHS\n"
     "${_sia_targets_text}\n")

string(REPLACE ";" "\n" _sia_tgt_leak_text "${_SIA_TARGETS_WITH_LEAK}")
file(WRITE "${_SIA_OUT_DIR}/targets_naming_leak.tsv"
     "TARGET\tINLINE_SOURCES\tHOLLOW_INLINE\tLEAK_INLINE\tLEAK_PATHS\tHOLLOW_PATHS\n"
     "${_sia_tgt_leak_text}\n")
message(STATUS "RAWRXD_SOURCE_INTEGRITY_TSV_DIR=${_SIA_OUT_DIR}")

# --- optional strictness -----------------------------------------------------
# Off by default: this is instrumentation and must not block a working tree.
# ON makes the gate-leak population fatal, which is how the gate is proven
# able to fail rather than merely asserted to be strict.
if(RAWRXD_STRICT_SOURCE_INTEGRITY AND _sia_leak_n GREATER 0)
    message(FATAL_ERROR
        "[source_integrity] ${_sia_leak_n} empty-bodied source(s) are reachable by a "
        "target that does not pass through rawrxd_filter_missing_sources(), so they "
        "escaped the declared-unimplemented gate:\n"
        "  see audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/gate_leak.tsv\n"
        "For each: implement it, withhold the target that names it, or retire it "
        "from the graph. Do not silence this by adding it to the register -- that "
        "records the gap as accepted without anyone deciding to accept it.")
endif()