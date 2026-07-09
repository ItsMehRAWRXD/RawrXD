cmake_minimum_required(VERSION 3.16)
project(SEG VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SEG_SOURCES
    seg_node.cpp
    seg_graph.cpp
    seg_scheduler.cpp
    seg_memory.cpp
    seg_executor.cpp
    seg_agent.cpp
    seg_runtime.cpp
    seg_models.cpp
    seg_telemetry_view.cpp
)

set(SEG_HEADERS
    seg_node.hpp
    seg_graph.hpp
    seg_scheduler.hpp
    seg_memory.hpp
    seg_executor.hpp
    seg_agent.hpp
    seg_runtime.hpp
    seg_models.hpp
    seg_telemetry_view.hpp
)

# Create library
add_library(seg STATIC ${SEG_SOURCES} ${SEG_HEADERS})

# Platform-specific settings
if(WIN32)
    target_compile_definitions(seg PRIVATE _WIN32_WINNT=0x0A00)
    target_link_libraries(seg PRIVATE)
else()
    target_link_libraries(seg PRIVATE pthread)
endif()

# Include directories
target_include_directories(seg PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Compiler options
if(MSVC)
    target_compile_options(seg PRIVATE /W4 /WX- /O2 /arch:AVX2)
    target_compile_options(seg PRIVATE /EHsc)
else()
    target_compile_options(seg PRIVATE -Wall -Wextra -O3 -march=native)
endif()

# Optional: MASM integration
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../masm_kernels")
    # Link MASM object files if present
    file(GLOB MASM_OBJS "${CMAKE_CURRENT_SOURCE_DIR}/../masm_kernels/*.obj")
    if(MASM_OBJS)
        target_sources(seg PRIVATE ${MASM_OBJS})
        message(STATUS "Found MASM kernels: ${MASM_OBJS}")
    endif()
endif()

# Example executable
add_executable(seg_example example.cpp)
target_link_libraries(seg_example PRIVATE seg)

# Install
install(TARGETS seg seg_example
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${SEG_HEADERS} DESTINATION include/seg)
