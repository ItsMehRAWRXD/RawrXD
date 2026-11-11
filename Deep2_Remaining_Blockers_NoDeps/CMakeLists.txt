cmake_minimum_required(VERSION 3.20)
project(Deep2RemainingBlockersNoDeps LANGUAGES CXX)

add_executable(deep2_cert deep2_cert_main.cpp)
target_compile_features(deep2_cert PRIVATE cxx_std_20)
target_include_directories(deep2_cert PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

if(MSVC)
    target_compile_options(deep2_cert PRIVATE /W4 /permissive-)
else()
    target_compile_options(deep2_cert PRIVATE -Wall -Wextra -Wpedantic)
endif()
