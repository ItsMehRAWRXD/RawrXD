cmake_minimum_required(VERSION 3.20)
project(RawrXDSpeculativeSpecialGraph LANGUAGES CXX)

add_library(rawrxd_speculative STATIC
    src/deep2/speculative/SpecialGraph.cpp
    src/deep2/speculative/SpeculativeBatch.cpp
    src/deep2/speculative/SpeculativeExecutor.cpp
    src/deep2/speculative/KvTransaction.cpp
    src/deep2/speculative/VerifyBatch.cpp
    src/deep2/speculative/DraftPolicy.cpp
    src/deep2/speculative/AcceptanceOracle.cpp
    src/deep2/speculative/DualGpuOverlap.cpp
    src/deep2/speculative/SpeculativeCert.cpp
)

target_include_directories(rawrxd_speculative PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/speculative
)
target_compile_features(rawrxd_speculative PUBLIC cxx_std_20)

add_executable(rawrxd_speculative_selftest
    tests/SpeculativeGraphSelfTest.cpp
)
target_link_libraries(rawrxd_speculative_selftest PRIVATE rawrxd_speculative)
target_compile_features(rawrxd_speculative_selftest PRIVATE cxx_std_20)

add_executable(rawrxd_speculative_infrastructure_selftest
    tests/SpeculativeInfrastructureSelfTest.cpp
)
target_link_libraries(rawrxd_speculative_infrastructure_selftest PRIVATE rawrxd_speculative)
target_compile_features(rawrxd_speculative_infrastructure_selftest PRIVATE cxx_std_20)
