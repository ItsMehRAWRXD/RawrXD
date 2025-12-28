cmake_minimum_required(VERSION 3.16)
project(AmazonQPlugin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Test)

# Plugin sources
set(PLUGIN_SOURCES
    amazonqplugin.cpp
    bedrocklient.cpp
    chatwidget.cpp
    completionprovider.cpp
)

set(PLUGIN_HEADERS
    amazonqplugin.h
    bedrocklient.h
    chatwidget.h
    completionprovider.h
)

# Create the plugin library
add_library(AmazonQPlugin SHARED ${PLUGIN_SOURCES} ${PLUGIN_HEADERS})

target_link_libraries(AmazonQPlugin
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

# Test executable
add_executable(test_amazonq_plugin test_amazonq_plugin.cpp ${PLUGIN_SOURCES})

target_link_libraries(test_amazonq_plugin
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Test
)

# Enable testing
enable_testing()
add_test(NAME AmazonQPluginTest COMMAND test_amazonq_plugin)