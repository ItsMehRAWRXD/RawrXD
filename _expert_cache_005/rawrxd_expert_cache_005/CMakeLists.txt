cmake_minimum_required(VERSION 3.20)
project(RawrXDExpertCache005 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
add_library(rawrxd_expert_cache_005 STATIC
    src/Deep2StackGuard.cpp
    src/ExpertScheduler.cpp)
target_include_directories(rawrxd_expert_cache_005 PUBLIC src)
add_executable(test_batch005 tests/test_batch005.cpp)
target_link_libraries(test_batch005 PRIVATE rawrxd_expert_cache_005)
