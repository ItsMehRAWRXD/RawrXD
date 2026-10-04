# =============================================================================
# nqb_vocab_setup.cmake -- produce the two fixtures the negative matrix needs.
#
# RAWRXD_NQBRAID_CTEST_001
#
# nqb_tokenizer_matrix.exe derives every corruption case from a known-good file
# and also needs a LEGACY file (one that declares no tokenizer section) to prove
# backward compatibility. Both are produced here so the negative test is
# self-contained.
# =============================================================================

if(NOT DEFINED WRITER OR NOT DEFINED OUTDIR)
    message(FATAL_ERROR "nqb_vocab_setup.cmake requires -DWRITER -DOUTDIR")
endif()

file(MAKE_DIRECTORY "${OUTDIR}")
file(MAKE_DIRECTORY "${OUTDIR}/cases")

# Tokenizer-aware good file.
execute_process(
    COMMAND "${WRITER}" --out "${OUTDIR}/dense_q1.nqb" --layers 2 --quant 1
    RESULT_VARIABLE good_rc
    OUTPUT_VARIABLE good_out
    ERROR_VARIABLE  good_err
)
if(NOT good_rc EQUAL 0 OR NOT good_out MATCHES "WRITE_OK=1")
    message(FATAL_ERROR "good fixture failed rc=${good_rc}\n${good_out}\n${good_err}")
endif()

# Legacy class: valid file, NO tokenizer section.
execute_process(
    COMMAND "${WRITER}" --out "${OUTDIR}/legacy.nqb" --layers 2 --quant 1 --no-vocab
    RESULT_VARIABLE legacy_rc
    OUTPUT_VARIABLE legacy_out
    ERROR_VARIABLE  legacy_err
)
if(NOT legacy_rc EQUAL 0 OR NOT legacy_out MATCHES "WRITE_OK=1")
    message(FATAL_ERROR "legacy fixture failed rc=${legacy_rc}\n${legacy_out}\n${legacy_err}")
endif()

message(STATUS "fixtures ready in ${OUTDIR}")