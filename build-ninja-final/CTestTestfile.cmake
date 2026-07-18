# CMake generated Testfile for 
# Source directory: D:/src
# Build directory: D:/src/build-ninja-final
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[smoke_test_measurement_integration]=] "D:/src/build-ninja-final/bin/smoke_test_measurement_integration.exe")
set_tests_properties([=[smoke_test_measurement_integration]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/src/CMakeLists.txt;6799;add_test;D:/src/CMakeLists.txt;0;")
add_test([=[e2e_integration_test]=] "D:/src/build-ninja-final/bin/e2e_integration_test.exe")
set_tests_properties([=[e2e_integration_test]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/src/CMakeLists.txt;6815;add_test;D:/src/CMakeLists.txt;0;")
add_test([=[agent_workflow_orchestrator_smoke]=] "D:/src/build-ninja-final/bin/agent_workflow_orchestrator_smoke.exe")
set_tests_properties([=[agent_workflow_orchestrator_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/src/CMakeLists.txt;6843;add_test;D:/src/CMakeLists.txt;0;")
add_test([=[RawrXD-GhostSoak]=] "D:/src/build-ninja-final/bin/RawrXD-GhostSoak.exe" "--iterations" "200" "--max-inflight" "16" "--timeout-ms" "1500")
set_tests_properties([=[RawrXD-GhostSoak]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/src/CMakeLists.txt;6870;add_test;D:/src/CMakeLists.txt;0;")
subdirs("src/semantic_index")
subdirs("src/completion")
subdirs("src")
subdirs("src/reverse_engineering")
subdirs("src/codex")
subdirs("src/tools/tokenizer_roundtrip_test")
subdirs("src/ast_parser")
subdirs("src/autocomplete_integration")
subdirs("tests")
subdirs("src/tools")
