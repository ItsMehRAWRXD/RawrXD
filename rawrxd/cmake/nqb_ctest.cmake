# =============================================================================
# RAWRXD_NQBRAID_CTEST_001
#
# The NanoF32Braid tranche was previously exercised by hand with ad-hoc `cl`
# invocations, which meant a clean checkout could not reproduce any of it and
# `ctest` reported nothing about a subsystem that had twelve passing cells.
#
# Two things are registered here, and the second matters more than the first:
#
#   1. POSITIVE tests -- the real shape x codec matrix. Twelve entries, not one
#      "happy path" entry, because the whole point of the matrix is that every
#      architecture reaches execution under every encoding. A single test would
#      have kept passing while three architectures were unreachable.
#
#   2. NEGATIVE tests -- the tokenizer corruption matrix. These are registered
#      with WILL_FAIL so that a corruption case which is ACCEPTED shows up as a
#      ctest failure. That inversion is the point: for a negative test, being
#      wrong in the direction of "rejected a good file" and being wrong in the
#      direction of "accepted a corrupt file" are opposite bugs, and only one of
#      them is caught by asserting an exit code.
#
# The matrix tests are driven through a CMake script rather than a bare command
# because each cell is a two-step sequence -- generate the fixture, then run the
# end-to-end test against it -- and `add_test` cannot express that directly.
# =============================================================================

set(NQB_CTEST_DIR "${CMAKE_BINARY_DIR}/nqb_ctest")
file(MAKE_DIRECTORY "${NQB_CTEST_DIR}")

# --- the two tools ----------------------------------------------------------
#
# Guarded, because another lane may already have declared them. Declaring a
# target twice is a hard configure error ("another target with the same name
# already exists"), and a duplicate here would block the ENTIRE configure --
# not just this subsystem. An `if(NOT TARGET ...)` keeps the include additive.
if(NOT TARGET nanof32_braid_writer)
    add_executable(nanof32_braid_writer
        tools/nanof32_braid_writer.cpp
        src/deep2/Nanof32BraidWriter.cpp
    )
    target_link_libraries(nanof32_braid_writer PRIVATE InferenceEngine)
    if(MSVC)
        target_compile_options(nanof32_braid_writer PRIVATE /arch:AVX512 /EHsc /W4 /std:c++20)
    endif()
    target_include_directories(nanof32_braid_writer PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(nanof32_braid_writer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

if(NOT TARGET nqb_tokenizer_matrix)
    add_executable(nqb_tokenizer_matrix
        tools/nqb_tokenizer_matrix.cpp
    )
    target_link_libraries(nqb_tokenizer_matrix PRIVATE InferenceEngine)
    if(MSVC)
        target_compile_options(nqb_tokenizer_matrix PRIVATE /arch:AVX512 /EHsc /W4 /std:c++20)
    endif()
    target_include_directories(nqb_tokenizer_matrix PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(nqb_tokenizer_matrix PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# --- driver script for one matrix cell --------------------------------------
# One cell = write a fixture with the given geometry/encoding, then run the
# end-to-end test over it. A failure in either step fails the cell.
set(NQB_CELL_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/nqb_matrix_cell.cmake")

# arch|quant|extra,args
#
# The extra args use COMMAS, not semicolons: a semicolon is CMake's own list
# separator, so an entry like "mla|0|--rope;3" splits into three list elements
# and every subsequent list(GET) reads out of range. That produced eight
# "list given N arguments, expected 2" configure errors.
set(NQB_CELLS
    "dense|0|"
    "dense|1|"
    "dense|5|"
    "mla|0|--rope,3"
    "mla|1|--rope,3"
    "mla|5|--rope,3"
    "moe|0|--experts,8"
    "moe|1|--experts,8"
    "moe|5|--experts,8"
    "mla_moe|0|--rope,3,--experts,8"
    "mla_moe|1|--rope,3,--experts,8"
    "mla_moe|5|--rope,3,--experts,8"
)

foreach(cell IN LISTS NQB_CELLS)
    string(REPLACE "|" ";" parts "${cell}")
    list(GET parts 0 arch)
    list(GET parts 1 quant)
    list(LENGTH parts part_count)
    set(extra "")
    if(part_count GREATER 2)
        list(GET parts 2 extra)
        string(REPLACE "," ";" extra "${extra}")
        list(JOIN " " extra_flat "${extra}")
    else()
        set(extra_flat "")
    endif()

    set(nqb_out "${NQB_CTEST_DIR}/${arch}_q${quant}.nqb")
    add_test(NAME nqb_${arch}_q${quant}
        COMMAND ${CMAKE_COMMAND}
            -DWRITER=$<TARGET_FILE:nanof32_braid_writer>
            -DTESTER=$<TARGET_FILE:nanof32_e2e_test>
            -DOUT=${nqb_out}
            -DQUANT=${quant}
            "-DEXTRA=${extra_flat}"
            -DTOKENS=16
            -P ${NQB_CELL_SCRIPT}
    )
endforeach()

# 128-token depth, one cell per architecture (not per codec: the depth axis is
# orthogonal to the encoding axis and all three encodings are already covered).
foreach(arch IN ITEMS dense mla moe mla_moe)
    set(extra_flat "")
    if(arch STREQUAL "mla" OR arch STREQUAL "mla_moe")
        set(extra_flat "--rope 3")
    endif()
    if(arch STREQUAL "moe" OR arch STREQUAL "mla_moe")
        if(extra_flat STREQUAL "")
            set(extra_flat "--experts 8")
        else()
            set(extra_flat "${extra_flat} --experts 8")
        endif()
    endif()

    add_test(NAME nqb_128tok_${arch}
        COMMAND ${CMAKE_COMMAND}
            -DWRITER=$<TARGET_FILE:nanof32_braid_writer>
            -DTESTER=$<TARGET_FILE:nanof32_e2e_test>
            -DOUT=${NQB_CTEST_DIR}/${arch}_128tok.nqb
            -DQUANT=1
            "-DEXTRA=${extra_flat}"
            -DTOKENS=128
            -P ${NQB_CELL_SCRIPT}
    )
endforeach()

# --- negative: tokenizer corruption matrix ---------------------------------
#
# The good fixture and the legacy (no-tokenizer) fixture are produced first, so
# the negative test is self-contained and does not depend on a manual step.
add_test(NAME nqb_vocab_setup
    COMMAND ${CMAKE_COMMAND}
        -DWRITER=$<TARGET_FILE:nanof32_braid_writer>
        -DOUTDIR=${NQB_CTEST_DIR}
        -P ${CMAKE_SOURCE_DIR}/cmake/nqb_vocab_setup.cmake
)

add_test(NAME nqb_tokenizer_negative
    COMMAND $<TARGET_FILE:nqb_tokenizer_matrix>
        --good ${NQB_CTEST_DIR}/dense_q1.nqb
        --outdir ${NQB_CTEST_DIR}/cases
        --legacy ${NQB_CTEST_DIR}/legacy.nqb
)
set_tests_properties(nqb_tokenizer_negative PROPERTIES
    DEPENDS nqb_vocab_setup
    FAIL_REGULAR_EXPRESSION "UNEXPECTED_ACCEPTS=[1-9]|UNEXPECTED_REJECTS=[1-9]|VERDICT=FAIL"
)

message(STATUS "[Deep2] NQBraid ctest: 12 matrix cells + 4 depth cells + 2 negative tests")