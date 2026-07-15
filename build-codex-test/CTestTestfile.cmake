# CMake generated Testfile for 
# Source directory: D:/rawrxd
# Build directory: D:/rawrxd/build-codex-test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[smoke_test_measurement_integration]=] "D:/rawrxd/build-codex-test/bin/smoke_test_measurement_integration.exe")
set_tests_properties([=[smoke_test_measurement_integration]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6538;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[e2e_integration_test]=] "D:/rawrxd/build-codex-test/bin/e2e_integration_test.exe")
set_tests_properties([=[e2e_integration_test]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6554;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[agent_workflow_orchestrator_smoke]=] "D:/rawrxd/build-codex-test/bin/agent_workflow_orchestrator_smoke.exe")
set_tests_properties([=[agent_workflow_orchestrator_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6582;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[RawrXD-GhostSoak]=] "D:/rawrxd/build-codex-test/bin/RawrXD-GhostSoak.exe" "--iterations" "200" "--max-inflight" "16" "--timeout-ms" "1500")
set_tests_properties([=[RawrXD-GhostSoak]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6609;add_test;D:/rawrxd/CMakeLists.txt;0;")
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
