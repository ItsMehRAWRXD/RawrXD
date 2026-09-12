cmake_minimum_required(VERSION 3.16)
project(DEEP2_ROOFLINE_LOCALITY_001_NODEP LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(deep2_locality64 STATIC
    src/deep2/Deep2Locality64.cpp)
target_include_directories(deep2_locality64 PUBLIC src/deep2)
add_executable(locality64_selftest tests/locality64_selftest.cpp)
target_link_libraries(locality64_selftest PRIVATE deep2_locality64)
