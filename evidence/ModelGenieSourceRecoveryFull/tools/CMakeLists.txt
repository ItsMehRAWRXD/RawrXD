cmake_minimum_required(VERSION 3.20)
project(RawrXD_ModelGenie_Tools VERSION 1.0 LANGUAGES CXX)

# RawrXD ModelGenie Compiler Tools
# RAWRXD_MODEL_GENIE_HEADER_EXPORT_001

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(Threads REQUIRED)

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/../src
    ${CMAKE_SOURCE_DIR}/../src/deep2
    ${CMAKE_SOURCE_DIR}/../src/deep2/modelgenie
)

# Header export tool
add_executable(rawrxd_modelgenie_header_export
    ../src/deep2/modelgenie/ModelGenome.cpp
    ../src/deep2/modelgenie/ModelGenomeReader.cpp
    ../src/deep2/modelgenie/ModelGenomeValidator.cpp
    ../src/deep2/modelgenie/HeaderEmitter.cpp
    rawrxd_modelgenie_header_export.cpp
)

target_link_libraries(rawrxd_modelgenie_header_export PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)

# Round-trip parity tool
add_executable(rawrxd_modelgenie_roundtrip
    ../src/deep2/modelgenie/ModelGenome.cpp
    ../src/deep2/modelgenie/ModelGenomeReader.cpp
    ../src/deep2/modelgenie/ModelGenomeValidator.cpp
    rawrxd_modelgenie_roundtrip.cpp
)

target_link_libraries(rawrxd_modelgenie_roundtrip PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)

# Runtime consumption probe
add_executable(rawrxd_modelgenie_runtime_probe
    rawrxd_modelgenie_runtime_probe.cpp
)

file(REAL_PATH "${CMAKE_SOURCE_DIR}/.." PROJECT_ROOT)
file(REAL_PATH "${PROJECT_ROOT}/src" SRC_DIR)
file(REAL_PATH "${PROJECT_ROOT}/src/deep2" DEEP2_DIR)
file(REAL_PATH "${PROJECT_ROOT}/src/deep2/modelgenie" MODELGENIE_DIR)
file(REAL_PATH "${PROJECT_ROOT}/generated/DeepSeek-V2-Lite-Chat" GENERATED_DIR)

target_include_directories(rawrxd_modelgenie_runtime_probe PRIVATE
    ${PROJECT_ROOT}
    ${SRC_DIR}
    ${DEEP2_DIR}
    ${MODELGENIE_DIR}
    ${GENERATED_DIR}
)

target_link_libraries(rawrxd_modelgenie_runtime_probe PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)

# Token-0 execution gate
add_executable(rawrxd_modelgenie_token0_execution
    rawrxd_modelgenie_token0_execution.cpp
)

get_filename_component(PROJECT_ROOT "${CMAKE_SOURCE_DIR}/.." ABSOLUTE)
get_filename_component(SRC_DIR "${PROJECT_ROOT}/src" ABSOLUTE)
get_filename_component(DEEP2_DIR "${SRC_DIR}/deep2" ABSOLUTE)
get_filename_component(MODELGENIE_DIR "${DEEP2_DIR}/modelgenie" ABSOLUTE)
get_filename_component(GENERATED_DIR "${PROJECT_ROOT}/generated/DeepSeek-V2-Lite-Chat" ABSOLUTE)

target_include_directories(rawrxd_modelgenie_token0_execution PRIVATE
    ${PROJECT_ROOT}
    ${SRC_DIR}
    ${DEEP2_DIR}
    ${MODELGENIE_DIR}
    ${GENERATED_DIR}
)

target_link_libraries(rawrxd_modelgenie_token0_execution PRIVATE
    Threads::Threads
    kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32 version ws2_32 psapi
)

message(STATUS "ModelGenie tools configured successfully")