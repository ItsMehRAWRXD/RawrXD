cmake_minimum_required(VERSION 3.20)
project(RawrXDExtensionPolicyGates LANGUAGES CXX)
# Standalone model-free acceptance harness, not a VSIX runtime certification.
add_executable(rawrxd_extension_policy_gates ../extension_policy_gates.cpp)
target_compile_features(rawrxd_extension_policy_gates PRIVATE cxx_std_17)
target_include_directories(rawrxd_extension_policy_gates PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../~dev/rawrxd/src/core")
if(MSVC)
  target_compile_options(rawrxd_extension_policy_gates PRIVATE /W4)
else()
  target_compile_options(rawrxd_extension_policy_gates PRIVATE -Wall -Wextra -Wpedantic)
endif()
enable_testing()
add_test(NAME rawrxd_extension_policy_gates COMMAND rawrxd_extension_policy_gates)

# Compile the actual fail-closed C ABI bridge, not a mock implementation.
add_executable(rawrxd_extension_bridge_failclosed
    ../extension_bridge_failclosed.cpp
    "../../~dev/rawrxd/src/core/js_extension_host_production.cpp")
target_compile_features(rawrxd_extension_bridge_failclosed PRIVATE cxx_std_17)
if(MSVC)
  target_compile_options(rawrxd_extension_bridge_failclosed PRIVATE /W4)
else()
  target_compile_options(rawrxd_extension_bridge_failclosed PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME rawrxd_extension_bridge_failclosed COMMAND rawrxd_extension_bridge_failclosed)
