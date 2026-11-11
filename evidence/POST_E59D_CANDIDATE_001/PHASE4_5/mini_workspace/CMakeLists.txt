cmake_minimum_required(VERSION 3.20)
project(rawrxd_phase4_mini LANGUAGES NONE)
add_custom_target(RawrXD-Win32IDE-Native
  COMMAND ${CMAKE_COMMAND}
    -DRESULT_FILE=${CMAKE_BINARY_DIR}/P45_BUILD_RESULT.txt
    -P ${CMAKE_CURRENT_SOURCE_DIR}/write_build_result.cmake
  VERBATIM)
enable_testing()
add_test(
  NAME phase4_mini_smoke
  COMMAND ${CMAKE_COMMAND}
    -DRESULT_FILE=${CMAKE_BINARY_DIR}/P45_TEST_RESULT.txt
    -P ${CMAKE_CURRENT_SOURCE_DIR}/write_test_result.cmake)
