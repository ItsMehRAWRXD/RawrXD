cmake_minimum_required(VERSION 3.20)
project(Deep2ServerlessAI LANGUAGES CXX)

add_executable(deep2-serverless deep2_serverless.cpp)
target_compile_features(deep2-serverless PRIVATE cxx_std_20)

if (MSVC)
    target_compile_options(deep2-serverless PRIVATE /W4 /EHsc /permissive-)
    target_link_libraries(deep2-serverless PRIVATE ws2_32)
else()
    target_compile_options(deep2-serverless PRIVATE -Wall -Wextra -Wpedantic)
    find_package(Threads REQUIRED)
    target_link_libraries(deep2-serverless PRIVATE Threads::Threads)
endif()
