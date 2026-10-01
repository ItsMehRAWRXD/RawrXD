cmake_minimum_required(VERSION 3.14)
project(scratch_workload LANGUAGES CXX)

add_library(workload src/workload.cpp)
target_include_directories(workload PUBLIC src)

add_executable(workload_test test/workload_test.cpp)
target_link_libraries(workload_test workload)