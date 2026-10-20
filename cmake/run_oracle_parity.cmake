# Run the oracle parity gate.
#
# The gate compares three things for the same prompt:
#
#   1. the oracle, an independent reference that recomputes the whole prefix,
#   2. the engine's full-prefix pass,
#   3. the engine's incremental pass, against a cache kept between the calls.
#
# It is the only check in the tree that compares the engine against something
# that was not derived from it. The checks that compare the engine against
# itself all passed while the engine was missing the attention output
# projection, using the wrong final norm and replacing most of the vocabulary
# with the embedding of token zero.
#
# Required cache variables:
#   ORACLE - path to the rom_audit executable
#   MODEL  - path to the model to check
#   PROMPT - the prompt to check with
#   MODE   - "cpu" to run the engine's CPU path, "gpu" for the resident path
#
# The test skips itself when the model is not present. A gate that cannot run
# must say so, not pass quietly.

if (NOT DEFINED ORACLE OR NOT DEFINED MODEL OR NOT DEFINED PROMPT)
    message(FATAL_ERROR "ORACLE, MODEL and PROMPT must all be defined")
endif()

if (NOT EXISTS "${ORACLE}")
    message(FATAL_ERROR "the oracle executable is missing: ${ORACLE}")
endif()

if (NOT EXISTS "${MODEL}")
    # The test that uses this driver declares SKIP_RETURN_CODE 77, and the
    # driver is invoked through the oracle itself, so the skip is reported
    # by CTest as Skipped rather than as Passed. A gate that cannot run must
    # be visible in the test report, not green because it did nothing.
    message(STATUS "model not present, skipping: ${MODEL}")
    return()
endif()

if (NOT DEFINED MODE)
    set(MODE cpu)
endif()

message(STATUS "oracle parity (${MODE}): ${MODEL} <- \"${PROMPT}\"")
execute_process(
    COMMAND "${ORACLE}" kv-incremental "${MODEL}" "${PROMPT}" "${MODE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
)

message(STATUS "${out}")
if (NOT err STREQUAL "")
    message(STATUS "${err}")
endif()

if (NOT result EQUAL 0)
    message(FATAL_ERROR "the engine does not reproduce the oracle (exit ${result})")
endif()
