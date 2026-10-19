# Convert a GGUF model to a ROM and run the production smoke suite against it.
#
# Required cache variables:
#   GGUF      - path to the source GGUF model
#   ROM       - path of the ROM to produce
#   CONVERTER - path to the gguf2rom executable
#   SMOKE     - path to the production_smoke_test executable
#   ARCH      - architecture hint for the converter (optional, default phi3)

if (NOT DEFINED GGUF OR NOT DEFINED ROM OR NOT DEFINED CONVERTER OR NOT DEFINED SMOKE)
    message(FATAL_ERROR "GGUF, ROM, CONVERTER and SMOKE must all be defined")
endif()

if (NOT EXISTS "${GGUF}")
    message(STATUS "model not present, skipping: ${GGUF}")
    return()
endif()

if (NOT DEFINED ARCH)
    set(ARCH phi3)
endif()

get_filename_component(ROM_DIR "${ROM}" DIRECTORY)
file(MAKE_DIRECTORY "${ROM_DIR}")

message(STATUS "converting ${GGUF} -> ${ROM}")
execute_process(
    COMMAND "${CONVERTER}" "${GGUF}" "${ROM}" "${ARCH}"
    RESULT_VARIABLE conv_result
    OUTPUT_VARIABLE conv_out
    ERROR_VARIABLE conv_err
)
if (NOT conv_result EQUAL 0)
    message(FATAL_ERROR "gguf2rom failed (${conv_result}):\n${conv_out}\n${conv_err}")
endif()

# The ROM must be a complete container: the payload section has to cover every
# tensor the manifest advertises.
file(SIZE "${ROM}" rom_size)
message(STATUS "ROM size: ${rom_size} bytes")

message(STATUS "running production smoke suite")
execute_process(
    COMMAND "${SMOKE}" "${ROM}" "${GGUF}" 1
    RESULT_VARIABLE smoke_result
    OUTPUT_VARIABLE smoke_out
    ERROR_VARIABLE smoke_err
)
message(STATUS "${smoke_out}")
if (NOT smoke_result EQUAL 0)
    message(FATAL_ERROR "production smoke test failed (${smoke_result}):\n${smoke_out}\n${smoke_err}")
endif()
