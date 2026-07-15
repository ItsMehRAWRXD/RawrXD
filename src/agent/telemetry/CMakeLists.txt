cmake_minimum_required(VERSION 3.20)

# Standalone stress test agent build
project(RawrXDStressAgent VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the stress test source
add_executable(stress_agent
    stress_test_agent.cpp
    AgentTelemetry_cpp_impl.cpp  # C++ implementation instead of MASM
)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(stress_agent PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
    
    # Link Windows libraries
    target_link_libraries(stress_agent PRIVATE
        kernel32
        user32
    )
endif()

# Optimization
if(MSVC)
    target_compile_options(stress_agent PRIVATE /O2 /EHsc)
else()
    target_compile_options(stress_agent PRIVATE -O2)
endif()

# Output to current directory
set_target_properties(stress_agent PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
