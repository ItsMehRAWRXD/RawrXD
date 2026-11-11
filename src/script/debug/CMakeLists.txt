# RawrXD-Script Debug Tools CMakeLists.txt
cmake_minimum_required(VERSION 3.20)

project(RawrXDScriptDebug VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find nlohmann_json
find_package(nlohmann_json REQUIRED)

# RawrXD-Script DAP Adapter executable
add_executable(rxd-script-dap
    rawrxd_script_dap_adapter.cpp
    main_dap_server.cpp
)

target_include_directories(rxd-script-dap PRIVATE
    ${CMAKE_SOURCE_DIR}/../../..
    ${CMAKE_SOURCE_DIR}/../../../lsp
)

target_link_libraries(rxd-script-dap PRIVATE
    nlohmann_json::nlohmann_json
)

# Register Live View library
add_library(rxd-script-debug STATIC
    register_live_view.cpp
)

target_include_directories(rxd-script-debug PUBLIC
    ${CMAKE_SOURCE_DIR}/../../..
)

# Install targets
install(TARGETS rxd-script-dap DESTINATION bin)
install(TARGETS rxd-script-debug DESTINATION lib)
