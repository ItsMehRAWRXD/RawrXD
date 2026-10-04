# =============================================================================
# nqb_matrix_cell.cmake -- drive ONE NanoF32Braid matrix cell.
#
# RAWRXD_NQBRAID_CTEST_001
#
# A cell is two steps and add_test() can only run one command, so this script
# does both:
#   1. generate the fixture with the writer
#   2. run the end-to-end test against it
#
# A failure at EITHER step fails the cell. That ordering matters: the writer
# refusing (VERDICT=FAIL, exit 1) and the test refusing (exit != 0) are
# different failures, and a driver that only checked the final exit code could
# not tell them apart. Both are checked and both are named.
# =============================================================================

if(NOT DEFINED WRITER OR NOT DEFINED TESTER OR NOT DEFINED OUT)
    message(FATAL_ERROR "nqb_matrix_cell.cmake requires -DWRITER -DTESTER -DOUT")
endif()
if(NOT DEFINED QUANT)
    set(QUANT 1)
endif()
if(NOT DEFINED TOKENS)
    set(TOKENS 16)
endif()
if(NOT DEFINED EXTRA)
    set(EXTRA "")
endif()

get_filename_component(out_dir "${OUT}" DIRECTORY)
file(MAKE_DIRECTORY "${out_dir}")

# --- step 1: write the fixture ----------------------------------------------
separate_arguments(extra_list UNIX_COMMAND "${EXTRA}")

execute_process(
    COMMAND "${WRITER}" --out "${OUT}" --layers 2 --quant "${QUANT}" ${extra_list}
    RESULT_VARIABLE write_rc
    OUTPUT_VARIABLE write_out
    ERROR_VARIABLE  write_err
)
message(STATUS "writer: ${write_rc}")
if(NOT write_rc EQUAL 0 OR NOT write_out MATCHES "WRITE_OK=1")
    message(FATAL_ERROR
        "WRITER FAILED rc=${write_rc}\n${write_out}\n${write_err}")
endif()
if(NOT write_out MATCHES "VERDICT=PASS")
    message(FATAL_ERROR "WRITER VERDICT != PASS\n${write_out}")
endif()

# --- step 2: run the end-to-end test ----------------------------------------
execute_process(
    COMMAND "${TESTER}" "${OUT}" "The capital of France is" "${TOKENS}"
    RESULT_VARIABLE test_rc
    OUTPUT_VARIABLE test_out
    ERROR_VARIABLE  test_err
)
message(STATUS "tester: ${test_rc}")
if(NOT test_rc EQUAL 0)
    message(FATAL_ERROR "E2E TEST FAILED rc=${test_rc}\n${test_out}\n${test_err}")
endif()

# The gates that must hold for every cell. Checked explicitly rather than
# trusted to the exit code, because an exit code of 0 with a degenerate result
# is exactly the failure this subsystem has produced before (all-zero logits
# read as "finite", and every sampled token was id 0).
foreach(required
        "RESULT=PASS"
        "TOKENIZER_WARNING_COUNT=0"
        "DUMMY_TOKENIZER_USED=0")
    if(NOT test_err MATCHES "${required}")
        message(FATAL_ERROR "missing required receipt field: ${required}\n${test_err}")
    endif()
endforeach()

if(NOT test_err MATCHES "LOGITS_SPREAD=([0-9]*\\.?[0-9]+)")
    message(FATAL_ERROR "no LOGITS_SPREAD in receipt; cannot rule out a degenerate run")
else()
    set(spread "${CMAKE_MATCH_1}")
    # A spread of exactly 0 means the logits buffer was never written.
    if(spread STREQUAL "0")
        message(FATAL_ERROR "degenerate logits: LOGITS_SPREAD=0")
    endif()
    message(STATUS "logits spread: ${spread}")
endif()

message(STATUS "CELL PASS ${OUT}")