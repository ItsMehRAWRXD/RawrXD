cmake_minimum_required(VERSION 3.16)
project(deep2_kimi_cost_nodep CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(kimi_cost_selftest KimiCostAuthority_Core.cpp
 KimiCostAuthority_Compare.cpp KimiCostAuthority_Emit.cpp selftest.cpp)
