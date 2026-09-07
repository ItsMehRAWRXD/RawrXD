# RAWRXD_AGENTIC_CLI_SOURCE_DROP_001
option(BUILD_RAWRXD_AGENTIC_CLI "Build agentic rawr CLI + certs" ON)
if(NOT BUILD_RAWRXD_AGENTIC_CLI)
  return()
endif()
if(NOT TARGET InferenceEngine)
  message(STATUS "[Deep2] Agentic CLI skipped (no InferenceEngine)")
  return()
endif()

set(RAWR_AGENTIC_SOURCES
  src/cli/rawr_main.cpp
  src/cli/rawr_commands.cpp
  src/cli/rawr_argument_parser.cpp
  src/cli/rawr_output_router.cpp
  src/cli/rawr_safety_policy.cpp
  src/cli/rawr_session_store.cpp
  src/cli/rawr_model_registry.cpp
  src/cli/rawr_console_repl.cpp
  src/cli/rawr_evidence_writer.cpp
  src/cli/rawr_context_window.cpp
  src/cli/rawr_transcript_log.cpp
  src/cli/rawr_history_compactor.cpp
  src/cli/rawr_resume.cpp
  src/cli/rawr_patch_engine.cpp
  src/cli/rawr_diff.cpp
  src/cli/rawr_patch_journal.cpp
  src/cli/rawr_undo_stack.cpp
  src/cli/rawr_file_snapshot.cpp
  src/cli/rawr_steering_bus.cpp
  src/cli/rawr_steering_server.cpp
  src/cli/rawr_steering_client.cpp
  src/cli/rawr_named_pipe.cpp
  src/cli/rawr_session_lock.cpp
  src/cli/rawr_permission_gate.cpp
  src/cli/rawr_path_guard.cpp
  src/cli/rawr_command_guard.cpp
  src/cli/rawr_network_guard.cpp
  src/cli/rawr_destructive_action_guard.cpp
  src/cli/rawr_agent_plan.cpp
  src/cli/rawr_agent_observer.cpp
  src/cli/rawr_agent_step.cpp
  src/cli/rawr_agent_executor.cpp
  src/cli/rawr_agent_loop.cpp
  src/cli/rawr_agent_tools.cpp
  src/cli/tools/rawr_file_tool.cpp
  src/cli/tools/rawr_search_tool.cpp
  src/cli/tools/rawr_patch_tool.cpp
  src/cli/tools/rawr_build_tool.cpp
  src/cli/tools/rawr_test_tool.cpp
  src/cli/tools/rawr_git_tool.cpp
  src/cli/tools/rawr_process_tool.cpp
  src/cli/tools/rawr_evidence_tool.cpp
  src/platform/rawr_win32_process.cpp
  src/cli/terminal/rawr_terminal_session.cpp
  src/cli/terminal/rawr_terminal_supervisor.cpp
  src/cli/terminal/rawr_terminal_host.cpp
  src/cli/terminal/rawr_terminal_client.cpp
  src/cli/terminal/rawr_terminal_commands.cpp
  src/cli/terminal/rawr_agent_terminal_tool.cpp
  src/deep2/Deep2SemanticSafeMode.cpp
  src/deep2/Deep2ChatSession.cpp
  src/deep2/Deep2GenerateStream.cpp
  src/deep2/Deep2PromptTemplate.cpp
  src/deep2/Deep2TokenizerAudit.cpp
  src/deep2/Deep2DetokenUtf8.cpp
  src/deep2/Deep2LogitsAudit.cpp
  src/deep2/Deep2SamplerAudit.cpp
  src/deep2/Deep2OutputProjectionAudit.cpp
  src/deep2/Deep2QuantParityAudit.cpp
)

# Replace thin rawr_run with agentic front door if rawr already defined.
if(TARGET rawr)
  get_target_property(_rawr_srcs rawr SOURCES)
  foreach(_s ${_rawr_srcs})
    if(_s MATCHES "rawr_run\\.cpp$")
      set_source_files_properties(${_s} PROPERTIES HEADER_FILE_ONLY TRUE)
    endif()
  endforeach()
  target_sources(rawr PRIVATE ${RAWR_AGENTIC_SOURCES})
  target_include_directories(rawr PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/cli/terminal
    ${CMAKE_SOURCE_DIR}/src/platform
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/include)
  # Prefer agentic main: exclude old entry by compiling it out.
  target_compile_definitions(rawr PRIVATE RAWR_AGENTIC_CLI=1)
  message(STATUS "[Deep2] rawr -> agentic CLI sources")
else()
  add_executable(rawr ${RAWR_AGENTIC_SOURCES})
  target_link_libraries(rawr PRIVATE InferenceEngine dxgi)
  if(MSVC)
    target_compile_options(rawr PRIVATE
      $<$<NOT:$<CONFIG:Debug>>:/O2> /arch:AVX512 /EHsc /W4 /std:c++20)
  endif()
  target_include_directories(rawr PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/include)
  set_target_properties(rawr PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    OUTPUT_NAME rawr
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

function(rawr_agent_cert name src)
  add_executable(${name} ${src})
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/include)
  if(MSVC)
    target_compile_options(${name} PRIVATE /EHsc /W3 /std:c++20)
  endif()
  set_target_properties(${name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

rawr_agent_cert(rawrxd_agentic_cli_001 certs/rawrxd_agentic_cli_001.cpp)
rawr_agent_cert(rawrxd_agent_session_001 certs/rawrxd_agent_session_001.cpp)
rawr_agent_cert(rawrxd_agent_tools_001 certs/rawrxd_agent_tools_001.cpp)
rawr_agent_cert(rawrxd_agent_patch_001 certs/rawrxd_agent_patch_001.cpp)
rawr_agent_cert(rawrxd_agent_build_test_001 certs/rawrxd_agent_build_test_001.cpp)
rawr_agent_cert(rawrxd_agent_steer_001 certs/rawrxd_agent_steer_001.cpp)
rawr_agent_cert(rawrxd_agent_safety_001 certs/rawrxd_agent_safety_001.cpp)
rawr_agent_cert(rawrxd_agent_resume_001 certs/rawrxd_agent_resume_001.cpp)
rawr_agent_cert(rawrxd_run_quality_001 certs/rawrxd_run_quality_001.cpp)
rawr_agent_cert(vwa_k2_prefetch_overlap_001_src certs/vwa_k2_prefetch_overlap_001.cpp)
rawr_agent_cert(vwa_bounded_k2_001 certs/vwa_bounded_k2_001.cpp)
rawr_agent_cert(k2_useful_tps_001_src certs/k2_useful_tps_001.cpp)

# Product unlock ladder U01/U02/U07/U09/U10/U15 (InferenceEngine-linked where needed)
function(rawr_ie_cert name src)
  add_executable(${name} ${src})
  target_link_libraries(${name} PRIVATE InferenceEngine dxgi)
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/include)
  if(MSVC)
    target_compile_options(${name} PRIVATE
      $<$<NOT:$<CONFIG:Debug>>:/O2> /arch:AVX512 /EHsc /W4 /std:c++20)
  endif()
  set_target_properties(${name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

rawr_ie_cert(rawrxd_stdout_clean_001 certs/rawrxd_stdout_clean_001.cpp)
rawr_ie_cert(rawrxd_no_ollama_contract_001 certs/rawrxd_no_ollama_contract_001.cpp)
rawr_agent_cert(rawrxd_auto_ladder_001 certs/rawrxd_auto_ladder_001.cpp)
rawr_agent_cert(rawrxd_chat_repl_001 certs/rawrxd_chat_repl_001.cpp)
rawr_agent_cert(rawrxd_product_frontdoor_001 certs/rawrxd_product_frontdoor_001.cpp)
rawr_agent_cert(rawrxd_embed_norm_guard_001 certs/rawrxd_embed_norm_guard_001.cpp)
rawr_agent_cert(rawrxd_decode_carry_001 certs/rawrxd_decode_carry_001.cpp)

# Product E2E climb (5 gates)
rawr_agent_cert(rawrxd_agent_workspace_live_001 certs/rawrxd_agent_workspace_live_001.cpp)
rawr_agent_cert(rawrxd_agent_loop_e2e_001 certs/rawrxd_agent_loop_e2e_001.cpp)
rawr_agent_cert(rawrxd_agent_steer_resume_001 certs/rawrxd_agent_steer_resume_001.cpp)
rawr_ie_cert(rawrxd_second_model_001 certs/rawrxd_second_model_001.cpp)
rawr_ie_cert(rawrxd_k2_product_e2e_001 certs/rawrxd_k2_product_e2e_001.cpp)
rawr_agent_cert(rawrxd_product_e2e_001 certs/rawrxd_product_e2e_001.cpp)

message(STATUS "[Deep2] RAWRXD_AGENTIC_CLI_SOURCE_DROP_001 wired")
