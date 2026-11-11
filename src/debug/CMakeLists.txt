# RawrXD Debug Backend CMakeLists.txt
# Professional Windows Debugger with DbgHelp Integration

cmake_minimum_required(VERSION 3.16)
project(RawrXD_DebugBackend VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Debug Backend Library
add_library(RawrXD_DebugBackend STATIC
    DebugBackend.cpp
    DebugBackend.h
)

target_include_directories(RawrXD_DebugBackend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(RawrXD_DebugBackend PUBLIC
    dbghelp.lib
    kernel32.lib
    user32.lib
)

# Test executable
add_executable(DebugTest
    DebugTest.cpp
)

target_link_libraries(DebugTest PRIVATE
    RawrXD_DebugBackend
)

# Set subsystem to console for test
set_target_properties(DebugTest PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)

# Vertical Slice Test executable
add_executable(VerticalTest
    VerticalTest.cpp
    DebugBackend.cpp
    DebugBridge.cpp
    DAPAdapter.cpp
)

target_include_directories(VerticalTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(VerticalTest PRIVATE
    dbghelp.lib
    kernel32.lib
    user32.lib
)

set_target_properties(VerticalTest PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)

# Install targets
install(TARGETS RawrXD_DebugBackend DebugTest
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES DebugBackend.h
    DESTINATION include/RawrXD
)
