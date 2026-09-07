# RawrRemainingStyleCli.fragment.cmake
option(BUILD_RAWR_REMAINING_STYLE_CLI "ChatGPT/Codex/Cursor style layer" ON)
if(NOT BUILD_RAWR_REMAINING_STYLE_CLI)
  return()
endif()

set(RAWR_STYLE_SOURCES
  src/cli/style/rawr_style_profiles.cpp
  src/cli/style/rawr_slash_commands.cpp
  src/cli/style/rawr_tool_directives.cpp
  src/cli/style/rawr_approval_queue.cpp
  src/cli/style/rawr_progress_renderer.cpp
  src/cli/style/rawr_diff_renderer.cpp
  src/cli/style/rawr_context_compactor.cpp
  src/cli/style/rawr_workspace_index.cpp
  src/cli/style/rawr_file_watcher.cpp
  src/cli/style/rawr_clipboard.cpp
  src/cli/style/rawr_diagnostic_scrubber.cpp
)

add_executable(rawrxd_remaining_style_cli_001
  certs/rawrxd_remaining_style_cli_001.cpp
  ${RAWR_STYLE_SOURCES})
target_include_directories(rawrxd_remaining_style_cli_001 PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/cli
  ${CMAKE_SOURCE_DIR}/src/cli/style)
if(MSVC)
  target_compile_options(rawrxd_remaining_style_cli_001 PRIVATE /EHsc /W3 /std:c++20)
endif()
set_target_properties(rawrxd_remaining_style_cli_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(TARGET rawr)
  target_sources(rawr PRIVATE ${RAWR_STYLE_SOURCES})
  target_include_directories(rawr PRIVATE
    ${CMAKE_SOURCE_DIR}/src/cli/style)
endif()

message(STATUS "[Deep2] RAWRXD_REMAINING_STYLE_CLI wired")
