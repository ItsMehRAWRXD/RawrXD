cmake_minimum_required(VERSION 3.15)
project(MyPlugin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RawrXD SDK
find_package(RawrXD REQUIRED)

# Create plugin library
add_library(MyPlugin SHARED
    MyPlugin.hpp
)

# Set plugin properties
set_target_properties(MyPlugin PROPERTIES
    PREFIX ""
    OUTPUT_NAME "MyPlugin"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
)

# Link against RawrXD SDK
target_link_libraries(MyPlugin
    RawrXD::PluginSDK
)

# Include directories
target_include_directories(MyPlugin PRIVATE
    ${RawrXD_INCLUDE_DIRS}
)

# Installation
install(TARGETS MyPlugin
    LIBRARY DESTINATION plugins
    RUNTIME DESTINATION plugins
)

# Print configuration message
message(STATUS "MyPlugin configured successfully")
message(STATUS "  Output directory: ${CMAKE_BINARY_DIR}/plugins")
