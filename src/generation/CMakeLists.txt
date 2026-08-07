cmake_minimum_required(VERSION 3.10)
project(RawrXDGeneration CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Module sources
set(GENERATION_SOURCES
    module1_types.h
    module2_cancel.h
    module3_utf8.h
    module4_stopstring.h
    module5_context.h
    module6_generate.h
    module7_glue.h
)

# Create interface library
add_library(RawrXDGeneration INTERFACE)

# Include directory
target_include_directories(RawrXDGeneration INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Dependencies
find_package(Threads REQUIRED)
target_link_libraries(RawrXDGeneration INTERFACE Threads::Threads)