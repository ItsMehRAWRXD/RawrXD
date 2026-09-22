cmake_minimum_required(VERSION 3.20)
project(rawrxd_screenpilot_bridge LANGUAGES CXX)

add_executable(rawrxd_screenpilot_bridge
    src/screenpilot_agent_bridge.cpp
)

target_compile_features(rawrxd_screenpilot_bridge PRIVATE cxx_std_20)
target_compile_definitions(rawrxd_screenpilot_bridge PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(rawrxd_screenpilot_bridge PRIVATE
    ws2_32
    bcrypt
)

if (MSVC)
    target_compile_options(rawrxd_screenpilot_bridge PRIVATE /W4 /permissive- /EHsc)
endif()
