# GA Blocker Tests
# Tests for components that must reach L3+ before GA

cmake_minimum_required(VERSION 3.16)

# Plugin SDK Tests
add_executable(test_plugin_sdk
    test_plugin_sdk.cpp
)

target_link_libraries(test_plugin_sdk
    PRIVATE
        RawrXD::Plugin
        gtest::gtest
)

add_test(NAME GA_PluginSDK_L3 COMMAND test_plugin_sdk)

# Real GGML Execution Tests
add_executable(test_real_ggml_execution
    test_real_ggml_execution.cpp
)

target_link_libraries(test_real_ggml_execution
    PRIVATE
        RawrXD::Runtime
        RawrXD::Backends
        gtest::gtest
)

add_test(NAME GA_RealGGML_L4 COMMAND test_real_ggml_execution)

# Extension Host Tests
add_executable(test_extension_host
    test_extension_host.cpp
)

target_link_libraries(test_extension_host
    PRIVATE
        RawrXD::ExtensionHost
        gtest::gtest
)

add_test(NAME GA_ExtensionHost_L3 COMMAND test_extension_host)

# Packaging Tests
add_executable(test_packaging
    test_packaging.cpp
)

target_link_libraries(test_packaging
    PRIVATE
        RawrXD::Core
        gtest::gtest
)

add_test(NAME GA_Packaging_L3 COMMAND test_packaging)

# Test labels for CI
set_tests_properties(
    GA_PluginSDK_L3
    GA_RealGGML_L4
    GA_ExtensionHost_L3
    GA_Packaging_L3
    PROPERTIES
        LABELS "ga_blocker"
)
