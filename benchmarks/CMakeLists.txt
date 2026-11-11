cmake_minimum_required(VERSION 3.16)
project(DeepSeekBenchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Benchmark executable
add_executable(deepseek_671b_benchmark
    deepseek_671b_benchmark.cpp
)

# Enable optimizations
target_compile_options(deepseek_671b_benchmark PRIVATE
    /O2
    /arch:AVX2
    /W4
)

# Link libraries
target_link_libraries(deepseek_671b_benchmark PRIVATE
    psapi
    pdh
)

# Install
install(TARGETS deepseek_671b_benchmark
    RUNTIME DESTINATION bin
)
