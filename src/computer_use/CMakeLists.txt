# Native Computer Use library (Win32 C++20). Linked by IDE candidates only.
cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(RawrXDComputerUse LANGUAGES CXX)
  set(CMAKE_SOURCE_DIR_SAVED "${CMAKE_SOURCE_DIR}")
endif()
if(NOT WIN32)
  message(FATAL_ERROR "rawrxd_computer_use is Windows-only")
endif()
if(NOT DEFINED CMAKE_SOURCE_DIR OR CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  # Standalone: parent src/ lives one level up for tool_core.hpp include.
  set(_RAWRXD_SRC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
else()
  set(_RAWRXD_SRC_ROOT "${CMAKE_SOURCE_DIR}/src")
endif()
add_library(rawrxd_computer_use STATIC
  ComputerUse.cpp
  ScreenCapture.cpp
  ComputerUseBridge.cpp
  ComputerUseParse.cpp)
target_compile_features(rawrxd_computer_use PUBLIC cxx_std_20)
target_include_directories(rawrxd_computer_use PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${_RAWRXD_SRC_ROOT})
target_compile_definitions(rawrxd_computer_use PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(rawrxd_computer_use PUBLIC user32 gdi32)
add_executable(rawrxd_computer_use_tests tests/ComputerUseTests.cpp)
target_link_libraries(rawrxd_computer_use_tests PRIVATE rawrxd_computer_use)
add_executable(rawrxd_computer_use_ide_verify tests/ComputerUseIdeVerify.cpp)
target_link_libraries(rawrxd_computer_use_ide_verify PRIVATE rawrxd_computer_use)
enable_testing()
add_test(NAME computer_use_policy_smoke COMMAND rawrxd_computer_use_tests)
add_test(NAME computer_use_ide_verify COMMAND rawrxd_computer_use_ide_verify)
