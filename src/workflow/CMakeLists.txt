# ============================================================================
# rawrxd_workflow — Dependency-free Browser Testing & GitHub Cloud Agents
# ============================================================================
# Builds the Cursor-like workflow tools (browser automation via
# WebView2, GitHub REST/cloud-agent via WinHTTP) as a static library.
# No Qt, no external dependencies beyond the vendored nlohmann/json
# and the Windows SDK. Safe to build in native dependency-free builds.
#
# Sources live in sibling directories (src/browser, src/github) and
# the bridge (src/agentic_workflow_bridge.cpp); paths below are
# relative to this file (src/workflow/).
# ============================================================================

add_library(rawrxd_workflow STATIC
    ../browser/BrowserTestEngine.cpp
    ../github/GitHubIntegration.cpp
    ../agentic_workflow_bridge.cpp
)

target_include_directories(rawrxd_workflow PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..          # src/ (for browser/, github/)
    ${CMAKE_CURRENT_SOURCE_DIR}/../..       # project root (for include/)
    ${CMAKE_SOURCE_DIR}/include             # vendored nlohmann/json
)

target_compile_definitions(rawrxd_workflow PRIVATE
    NOMINMAX
    _WIN32_WINNT=0x0A00
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(rawrxd_workflow PRIVATE /EHsc /wd4530 /wd4003 /wd4319 /wd4005)
    # WebView2/WinHTTP
    target_link_libraries(rawrxd_workflow PRIVATE winhttp)
endif()

message(STATUS "rawrxd_workflow: dependency-free browser testing & GitHub cloud agents enabled")
