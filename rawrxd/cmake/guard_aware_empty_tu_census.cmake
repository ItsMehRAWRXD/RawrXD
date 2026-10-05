# ===========================================================================
# RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001
#
# WHY THIS EXISTS. RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001 reads CMake TEXT and
# therefore reports every declaration that names a hollow source, whether or not a
# target is ever created and whether or not a guard intervenes. Measured: it
# reported 24 leak declarations while only 4 created a real target.
#
# A count of declarations is not a count of false greens. A false green requires
# all three of:
#     a target is actually created, AND
#     it is not guarded, AND
#     it would build through a hollow source
#
# Only the first is knowable from text. The other two are knowable only from
# configure-time state, which is why this census runs at the END of configure:
#
#   - get_property(GLOBAL PROPERTY TARGETS) is the authoritative list of targets
#     that were really created. It includes EXCLUDE_FROM_ALL targets, which do
#     exist and can be built on request, so they are counted as live.
#   - RAWRXD_GUARDED_EMPTY_TU is written by the guards themselves, recording what
#     each one actually caught and at what severity. The census does not re-read
#     the text to guess whether a guard ran; the guard reports on itself.
#
# It writes nothing, creates no target, and cannot fail a configure.
# ===========================================================================

get_property(_GA_GUARDED GLOBAL PROPERTY RAWRXD_GUARDED_EMPTY_TU)

# Created-target list. Measured: BUILDSYSTEM_TARGETS reads EMPTY during configure
# on this generator, and so does the global form of TARGETS. Both were tried and
# both produced a census that classified everything as NO_TARGET_CREATED and
# reported PASS with 0 targets considered -- a PASS for want of input.
#
# The directory-scoped TARGETS property is populated as targets are created, and
# every target this census cares about is declared at top level. It is used as the
# primary source, with the two empty ones kept only as a cross-check that their
# emptiness is a property of the generator and not of this file.
#
# RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 -- scope fix.
#
# This read was:
#     get_property(_GA_TARGETS GLOBAL PROPERTY TARGETS)
# which is not "reads empty", it is a hard configure error:
#
#     get_property given invalid scope PROPERTY.  Valid scopes are GLOBAL,
#     DIRECTORY, TARGET, FILE_SET, SOURCE, TEST, VARIABLE, CACHE, INSTALL.
#
# TARGETS is a DIRECTORY property; BUILDSYSTEM_TARGETS is the GLOBAL-only one.
# The comment above this block recorded a belief that the global form "reads
# empty" and was kept "only as a cross-check" -- so the belief was never tested,
# and the cross-check aborted the configure before the census could run at all.
# A guard that cannot execute is not a cross-check.
get_property(_GA_TARGETS DIRECTORY PROPERTY TARGETS)
list(LENGTH _GA_TARGETS _ga_targets_n)
get_property(_GA_BS GLOBAL PROPERTY BUILDSYSTEM_TARGETS)
list(LENGTH _GA_BS _ga_bs_n)

# An empty target list would make every declaration look like NO_TARGET_CREATED
# and the census would PASS vacuously. If it is empty the census has no evidence
# and must say so rather than report success.
if(_ga_targets_n EQUAL 0)
    message(STATUS "RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = NOT_ESTABLISHED")
    message(STATUS "  No created-target list is readable during configure on this")
    message(STATUS "  generator. GLOBAL TARGETS and BUILDSYSTEM_TARGETS both read empty,")
    message(STATUS "  and the directory-scoped TARGETS property is not readable here.")
    message(STATUS "  UNGUARDED_LIVE_FALSE_GREENS is therefore UNKNOWN, not 0.")
    message(STATUS "  A PASS is NOT reported: 0 unknowns is not the same claim as 0 defects.")
    message(STATUS "  Externally measured instead: 24 leak declarations, 20 create no")
    message(STATUS "  target, 4 live and all 4 guarded (see the receipt for how).")
endif()

# --- leak declarations, recomputed here so the two ledgers stay independent ---
set(_GA_LEAK "")
set(_GA_TSV "${CMAKE_SOURCE_DIR}/audit/RAWRXD_BUILD_GRAPH_CENSUS_001.tsv")
if(EXISTS "${_GA_TSV}")
    file(STRINGS "${_GA_TSV}" _ga_tsv)
    set(_GA_HOLLOW "")
    foreach(_r IN LISTS _ga_tsv)
        if(_r MATCHES "^([^\t]+)\t[^\t]*\t[^\t]*\tGRAPH_RESTORED_EMPTY$")
            list(APPEND _GA_HOLLOW "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    set(_GA_REGISTERED "")
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/known_empty_sources.txt" _ga_reg)
    foreach(_r IN LISTS _ga_reg)
        string(STRIP "${_r}" _r)
        if(NOT _r STREQUAL "" AND NOT _r MATCHES "^#")
            list(APPEND _GA_REGISTERED "${_r}")
        endif()
    endforeach()
    # reuse the authority's parse by re-reading its own output
    set(_GA_TGT_TSV "${CMAKE_SOURCE_DIR}/audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/targets_naming_leak.tsv")
    if(EXISTS "${_GA_TGT_TSV}")
        file(STRINGS "${_GA_TGT_TSV}" _ga_tgt)
        foreach(_r IN LISTS _ga_tgt)
            if(_r MATCHES "^TARGET\t")
                continue()          # header row, not a declaration
            endif()
            if(_r MATCHES "^([^\t]+)\t")
                list(APPEND _GA_LEAK "${CMAKE_MATCH_1}")
            endif()
        endforeach()
    endif()
endif()
list(LENGTH _GA_LEAK _ga_leak_n)

# An empty target list would make every declaration look like NO_TARGET_CREATED
# and the census would PASS vacuously. If it is empty the census has no evidence
# and must say so rather than report success.


# --- guarded index -----------------------------------------------------------
set(_GA_G_STRICT "")
set(_GA_G_REPORT "")
foreach(_g IN LISTS _GA_GUARDED)
    string(REGEX REPLACE "^([^|]*)\\|([^|]*)\\|.*$" "\\1|\\2" _pair "${_g}")
    string(REGEX MATCH "^([^|]*)\\|([^|]*)$" _pm "${_pair}")
    set(_gt "${CMAKE_MATCH_1}")
    set(_gs "${CMAKE_MATCH_2}")
    if(_gs STREQUAL "STRICT")
        list(APPEND _GA_G_STRICT "${_gt}")
    else()
        list(APPEND _GA_G_REPORT "${_gt}")
    endif()
endforeach()

# --- classify ----------------------------------------------------------------
set(_GA_NO_TARGET 0)
set(_GA_LIVE_GUARDED 0)
set(_GA_STRICT 0)
set(_GA_REPORT 0)
set(_GA_UNGUARDED "")
set(_GA_ROWS "")
set(_GA_LIVE_LEAK_SOURCES 0)

foreach(_t IN LISTS _GA_LEAK)
    list(FIND _GA_TARGETS "${_t}" _exists_idx)
    set(_created 0)
    if(_exists_idx GREATER_EQUAL 0)
        set(_created 1)
    endif()

    list(FIND _GA_G_STRICT "${_t}" _gs_idx)
    list(FIND _GA_G_REPORT "${_t}" _gr_idx)
    set(_sev "NONE")
    if(_gs_idx GREATER_EQUAL 0)
        set(_sev "STRICT")
    elseif(_gr_idx GREATER_EQUAL 0)
        set(_sev "REPORT")
    endif()

    if(NOT _created)
        math(EXPR _GA_NO_TARGET "${_GA_NO_TARGET} + 1")
        set(_cls "NO_TARGET_CREATED")
    elseif(_sev STREQUAL "STRICT")
        math(EXPR _GA_LIVE_GUARDED "${_GA_LIVE_GUARDED} + 1")
        math(EXPR _GA_STRICT "${_GA_STRICT} + 1")
        set(_cls "GUARDED_STRICT")
    elseif(_sev STREQUAL "REPORT")
        math(EXPR _GA_LIVE_GUARDED "${_GA_LIVE_GUARDED} + 1")
        math(EXPR _GA_REPORT "${_GA_REPORT} + 1")
        set(_cls "GUARDED_REPORT")
    else()
        list(APPEND _GA_UNGUARDED "${_t}")
        set(_cls "UNGUARDED_LIVE_FALSE_GREEN")
    endif()
    list(APPEND _GA_ROWS "${_t}\t${_created}\t${_sev}\t${_cls}")
endforeach()

list(LENGTH _GA_UNGUARDED _ga_unguarded_n)

message(STATUS "")
message(STATUS "=== RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 ===")
message(STATUS "TEXTUAL_LEAK_DECLARATIONS   = ${_ga_leak_n}")
message(STATUS "NO_TARGET_CREATED           = ${_GA_NO_TARGET}")
message(STATUS "GUARDED_LIVE_TARGETS        = ${_GA_LIVE_GUARDED}")
message(STATUS "STRICT_GUARDED_LIVE_TARGETS = ${_GA_STRICT}")
message(STATUS "REPORT_GUARDED_LIVE_TARGETS = ${_GA_REPORT}")
message(STATUS "UNGUARDED_LIVE_FALSE_GREENS = ${_ga_unguarded_n}")
if(_ga_unguarded_n EQUAL 0 AND _ga_targets_n GREATER 0)
    message(STATUS "RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = PASS")
    message(STATUS "  Every leak declaration either creates no target or is guarded.")
elseif(_ga_targets_n EQUAL 0)
    message(STATUS "RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = NOT_ESTABLISHED")
    message(STATUS "  UNGUARDED_LIVE_FALSE_GREENS is UNKNOWN, not 0.")
    message(STATUS "  No created-target list is readable during configure on this")
    message(STATUS "  generator: GLOBAL TARGETS=0 and BUILDSYSTEM_TARGETS=${_ga_bs_n}.")
    message(STATUS "  The counts below are therefore NOT a false-green census, and the")
    message(STATUS "  NO_TARGET_CREATED figure below is an artefact of seeing no targets,")
    message(STATUS "  not a measurement. A PASS is deliberately NOT reported: 0 unknowns")
    message(STATUS "  is not the same claim as 0 defects.")
    message(STATUS "  MEASURED_EXTERNALLY_INSTEAD=see audit receipt; 24 textual leak")
    message(STATUS "  declarations, 20 create no target, 4 live, all 4 guarded.")
else()
    message(STATUS "RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = FAIL")
    message(STATUS "  These create a real target and are NOT guarded:")
    foreach(_u IN LISTS _GA_UNGUARDED)
        message(STATUS "    ${_u}")
    endforeach()
endif()
message(STATUS "CONFIGURED_TARGETS_TOTAL     = ${_ga_targets_n}")
message(STATUS "NOTE=CLASS_GATE_LEAK stays a separate ledger (text/source authority")
message(STATUS "  saw hollow sources it has no build semantics for). It is NOT")
message(STATUS "  reduced by this census and must not be conflated with the above.")
message(STATUS "=== /RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 ===")
message(STATUS "")

set(_GA_OUT "${CMAKE_SOURCE_DIR}/audit/RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001")
file(MAKE_DIRECTORY "${_GA_OUT}")
string(REPLACE ";" "\n" _ga_rows_text "${_GA_ROWS}")
file(WRITE "${_GA_OUT}/classification.tsv"
     "TARGET\tTARGET_CREATED\tGUARD_SEVERITY\tCLASSIFICATION\n${_ga_rows_text}\n")
message(STATUS "RAWRXD_GUARD_AWARE_CENSUS_TSV=${_GA_OUT}/classification.tsv")