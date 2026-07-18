cmake_minimum_required(VERSION 3.16)
project(RawrXD_ToolCallingExample)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RawrXD
find_package(RawrXD REQUIRED)

# Tool Calling Example
add_executable(tool_calling_example
    main.cpp
    CalculatorTool.cpp
    WeatherTool.cpp
    FileSystemTool.cpp
)

target_link_libraries(tool_calling_example
    PRIVATE
        RawrXD::Runtime
        RawrXD::Agentic
)

# Install
install(TARGETS tool_calling_example
    RUNTIME DESTINATION bin/examples
)