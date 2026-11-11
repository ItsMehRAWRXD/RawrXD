# Security Module - Backend Health Monitor
set(BACKEND_HEALTH_MONITOR_SOURCES
    BackendHealthMonitor.cpp
)

add_library(backend_health_monitor STATIC
    ${BACKEND_HEALTH_MONITOR_SOURCES}
)

target_include_directories(backend_health_monitor PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(backend_health_monitor PUBLIC
    nlohmann_json::nlohmann_json
)
