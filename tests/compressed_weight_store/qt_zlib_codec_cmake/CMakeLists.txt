cmake_minimum_required(VERSION 3.20)
project(RawrXDQtZlibCodecRegression LANGUAGES CXX)
include(CTest)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Standalone integration check for Qt/zlib auto-detection and the actual codec TU.
# Explicitly fail when requested zlib support is missing: never silently skip the test.
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
    message(FATAL_ERROR "Qt/zlib codec regression requires zlib; auto-detection returned ZLIB_FOUND=FALSE")
endif()
add_executable(rawrxd_qt_zlib_codec_regression
    "${CMAKE_CURRENT_LIST_DIR}/../../../src/codec/compression.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/../test_qt_zlib_codec.cpp")
target_include_directories(rawrxd_qt_zlib_codec_regression PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../src")
target_link_libraries(rawrxd_qt_zlib_codec_regression PRIVATE Qt6::Core ZLIB::ZLIB)
if(BUILD_TESTING)
    add_test(NAME rawrxd_qt_zlib_codec_regression
             COMMAND rawrxd_qt_zlib_codec_regression)
endif()
