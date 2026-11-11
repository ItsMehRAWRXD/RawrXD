# Phase 18A: Feedback Collection Infrastructure
# Telemetry module for Personalized Intent Tuning

cmake_minimum_required(VERSION 3.16)

set(TELEMETRY_SOURCES
    FeedbackCollector.cpp
)

set(TELEMETRY_HEADERS
    FeedbackCollector.h
)

# Create telemetry library
add_library(telemetry STATIC ${TELEMETRY_SOURCES} ${TELEMETRY_HEADERS})

target_include_directories(telemetry
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# C++17 required for std::filesystem, std::optional, etc.
target_compile_features(telemetry PUBLIC cxx_std_17)

# Platform-specific settings
if(WIN32)
    target_link_libraries(telemetry PRIVATE shlwapi)
endif()

# Threading support
find_package(Threads REQUIRED)
target_link_libraries(telemetry PRIVATE Threads::Threads)

# Optional: SQLite for structured storage (Phase 18B+)
find_package(SQLite3 QUIET)
if(SQLite3_FOUND)
    target_compile_definitions(telemetry PRIVATE RAWR_HAS_SQLITE=1)
    target_link_libraries(telemetry PRIVATE SQLite::SQLite3)
endif()

# Install targets
install(TARGETS telemetry
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${TELEMETRY_HEADERS}
    DESTINATION include/telemetry
)
