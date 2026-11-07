cmake_minimum_required(VERSION 3.20)
project(RawrXDOfflineExtensionAcceptance LANGUAGES CXX)

# Independent native-C++ smoke lane: no GPU, Ollama, QuickJS, Qt or MASM.
get_filename_component(RAWRXD_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(RAWRXD_CLI_SOURCE "${RAWRXD_REPO_ROOT}/tools/rawrxd_extensions_cli.cpp")
if(NOT EXISTS "${RAWRXD_CLI_SOURCE}")
    message(FATAL_ERROR "RawrXD extensions CLI source missing")
endif()
add_executable(rawrxd-extensions "${RAWRXD_CLI_SOURCE}")
target_compile_features(rawrxd-extensions PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(rawrxd-extensions PRIVATE /W4 /WX /EHsc)
else()
    target_compile_options(rawrxd-extensions PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# The CLI is a real redistributable artifact, not just an in-tree test binary.
install(TARGETS rawrxd-extensions RUNTIME DESTINATION bin)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()
add_test(NAME offline-extensions-blackbox
    COMMAND "${CMAKE_COMMAND}" -E env
    "RAWRXD_EXTENSIONS_BIN=$<TARGET_FILE:rawrxd-extensions>"
    "${Python3_EXECUTABLE}" -m unittest discover
    -s "${RAWRXD_REPO_ROOT}/tests" -p test_offline_extensions_cli.py -v)
set_tests_properties(offline-extensions-blackbox PROPERTIES TIMEOUT 60)
