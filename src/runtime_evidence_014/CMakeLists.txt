cmake_minimum_required(VERSION 3.20)
project(rawr_runtime_evidence_014 LANGUAGES CXX)
add_executable(rawr-runtime-gates main.cpp)
target_compile_features(rawr-runtime-gates PRIVATE cxx_std_20)
