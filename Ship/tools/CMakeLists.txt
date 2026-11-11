cmake_minimum_required(VERSION 3.20)

<<<<<<< HEAD
# RawrXD_CLI is now built in parent CMakeLists with full agentic parity (chat + tools + Ollama).
# This subdir provides StressTest and other utilities only.
=======
# CLI Executable
add_executable(RawrXD_CLI cli_main.cpp)
target_include_directories(RawrXD_CLI PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(RawrXD_CLI PRIVATE ws2_32)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

# Stress Test Executable  
add_executable(RawrXD_StressTest stress_test.cpp)
target_include_directories(RawrXD_StressTest PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(RawrXD_StressTest PRIVATE ws2_32)

# Install targets
<<<<<<< HEAD
install(TARGETS RawrXD_StressTest RUNTIME DESTINATION bin)
=======
install(TARGETS RawrXD_CLI RawrXD_StressTest RUNTIME DESTINATION bin)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
