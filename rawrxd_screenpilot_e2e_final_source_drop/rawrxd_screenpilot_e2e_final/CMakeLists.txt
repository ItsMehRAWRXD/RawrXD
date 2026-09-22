cmake_minimum_required(VERSION 3.20)
project(rawrxd_screenpilot_e2e LANGUAGES CXX)

add_library(rawrxd_screenpilot_e2e STATIC
    src/rawrxd_screenpilot_agent_v2.cpp
)

target_include_directories(rawrxd_screenpilot_e2e PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(rawrxd_screenpilot_e2e PUBLIC cxx_std_20)
target_compile_definitions(rawrxd_screenpilot_e2e PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(rawrxd_screenpilot_e2e PUBLIC bcrypt)

if (MSVC)
    target_compile_options(rawrxd_screenpilot_e2e PRIVATE /W4 /permissive- /EHsc)
endif()
