cmake_minimum_required(VERSION 3.20)
project(e2e06 C)
add_executable(e2e06 main.c)
enable_testing()
add_test(NAME e2e06 COMMAND e2e06)

