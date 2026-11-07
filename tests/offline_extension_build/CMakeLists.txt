cmake_minimum_required(VERSION 3.20)
project(RawrXDOfflineExtensionAcceptance LANGUAGES CXX)

# Verify the very same CLI CMake fragment used by the native RawrXD build.
# No GPU, Ollama, QuickJS, Qt or MASM are required for this target.
get_filename_component(RAWRXD_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
include("${RAWRXD_REPO_ROOT}/~dev/rawrxd/cmake/OfflineExtensionsCli.cmake")
if(NOT TARGET RawrXD-ExtensionsCLI)
    message(FATAL_ERROR "RawrXD-ExtensionsCLI target not registered")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()
add_test(NAME offline-extensions-blackbox
    COMMAND "${CMAKE_COMMAND}" -E env
    "RAWRXD_EXTENSIONS_BIN=$<TARGET_FILE:RawrXD-ExtensionsCLI>"
    "${Python3_EXECUTABLE}" -m unittest discover
    -s "${RAWRXD_REPO_ROOT}/tests" -p test_offline_extensions_cli.py -v)
set_tests_properties(offline-extensions-blackbox PROPERTIES TIMEOUT 60)
