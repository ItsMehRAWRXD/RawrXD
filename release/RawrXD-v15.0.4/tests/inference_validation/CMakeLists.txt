cmake_minimum_required(VERSION 3.16)
project(RawrXDValidation)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Validation harness library
add_library(validation_harness STATIC
    harness/tensor_compare.cpp
    harness/reference_loader.cpp
)

target_include_directories(validation_harness PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

# Enable AVX-512 for tensor comparison
target_compile_options(validation_harness PRIVATE
    /arch:AVX512
    /O2
    /W4
)

# Validation runner executable
add_executable(validation_runner
    harness/validation_runner.cpp
)

target_link_libraries(validation_runner PRIVATE
    validation_harness
)

target_compile_options(validation_runner PRIVATE
    /arch:AVX512
    /O2
    /W4
)

# Smoke test executable
add_executable(validation_smoke
    test_validation_smoke.cpp
)

target_link_libraries(validation_smoke PRIVATE
    validation_harness
)

# Install targets
install(TARGETS validation_runner validation_smoke
    RUNTIME DESTINATION bin
)

install(FILES
    harness/tensor_compare.hpp
    harness/reference_loader.hpp
    harness/runtime_hooks.hpp
    DESTINATION include/rawrxd/validation
)
