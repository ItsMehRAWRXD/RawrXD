cmake_minimum_required(VERSION 3.16)
project(RawrXD_TelemetryDashboard)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RawrXD
find_package(RawrXD REQUIRED)

# Telemetry Dashboard Example
add_executable(telemetry_dashboard
    main.cpp
    MetricsCollector.cpp
    DashboardServer.cpp
)

target_link_libraries(telemetry_dashboard
    PRIVATE
        RawrXD::Runtime
        RawrXD::Telemetry
)

# Install
install(TARGETS telemetry_dashboard
    RUNTIME DESTINATION bin/examples
)