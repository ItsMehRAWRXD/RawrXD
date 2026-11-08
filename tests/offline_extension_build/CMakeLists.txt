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

# Actual no-model cancellation primitive: C++14, multiple concurrent waiters,
# stop wakeups, predicate transitions and independent A/B request tokens.
find_package(Threads REQUIRED)
add_executable(rawrxd-cancel-smoke "${RAWRXD_REPO_ROOT}/tests/cancel_token_smoke.cpp")
set_target_properties(rawrxd-cancel-smoke PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED ON)
target_link_libraries(rawrxd-cancel-smoke PRIVATE Threads::Threads)
if(MSVC)
    target_compile_options(rawrxd-cancel-smoke PRIVATE /W4 /WX /EHsc)
else()
    target_compile_options(rawrxd-cancel-smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_test(NAME cancel-token-no-model COMMAND $<TARGET_FILE:rawrxd-cancel-smoke>)
set_tests_properties(cancel-token-no-model PROPERTIES TIMEOUT 30)

# Separate actual inference cancellation primitive test (not a GUI T05 PASS).
add_executable(rawrxd-inference-cancel-smoke "${RAWRXD_REPO_ROOT}/tests/inference_cancel_smoke.cpp")
set_target_properties(rawrxd-inference-cancel-smoke PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_link_libraries(rawrxd-inference-cancel-smoke PRIVATE Threads::Threads)
if(MSVC)
    target_compile_options(rawrxd-inference-cancel-smoke PRIVATE /W4 /WX /EHsc)
else()
    target_compile_options(rawrxd-inference-cancel-smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_test(NAME inference-cancel-no-model COMMAND $<TARGET_FILE:rawrxd-inference-cancel-smoke>)
set_tests_properties(inference-cancel-no-model PROPERTIES TIMEOUT 30)

# Model-free agent MUTATION AUTHORIZATION gate; on unsupported cryptographic
# platforms positive authorization fails closed and negative cases still run.
add_executable(rawrxd-motd-smoke "${RAWRXD_REPO_ROOT}/tests/motd_authorization_smoke.cpp")
set_target_properties(rawrxd-motd-smoke PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
if(MSVC)
    target_compile_options(rawrxd-motd-smoke PRIVATE /W4 /WX /EHsc)
else()
    target_compile_options(rawrxd-motd-smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_test(NAME motd-authorization-no-model COMMAND $<TARGET_FILE:rawrxd-motd-smoke>)
set_tests_properties(motd-authorization-no-model PROPERTIES TIMEOUT 30)
