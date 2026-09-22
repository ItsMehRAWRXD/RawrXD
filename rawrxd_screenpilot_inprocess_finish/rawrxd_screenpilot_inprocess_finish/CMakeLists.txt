cmake_minimum_required(VERSION 3.20)
project(rawrxd_screenpilot_inprocess LANGUAGES CXX)

add_library(rawrxd_screenpilot_inprocess STATIC
    src/rawrxd_screenpilot_agent.cpp
)

target_include_directories(rawrxd_screenpilot_inprocess PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(rawrxd_screenpilot_inprocess PUBLIC cxx_std_20)

target_compile_definitions(rawrxd_screenpilot_inprocess PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(rawrxd_screenpilot_inprocess PUBLIC bcrypt)

if (MSVC)
    target_compile_options(rawrxd_screenpilot_inprocess PRIVATE /W4 /permissive- /EHsc)
endif()
