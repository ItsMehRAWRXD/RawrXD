# CMake generated Testfile for 
# Source directory: D:/rawrxd
# Build directory: D:/rawrxd/build-ninja
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[smoke_test_measurement_integration]=] "D:/rawrxd/build-ninja/bin/smoke_test_measurement_integration.exe")
set_tests_properties([=[smoke_test_measurement_integration]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6186;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[e2e_integration_test]=] "D:/rawrxd/build-ninja/bin/e2e_integration_test.exe")
set_tests_properties([=[e2e_integration_test]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6202;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[agent_workflow_orchestrator_smoke]=] "D:/rawrxd/build-ninja/bin/agent_workflow_orchestrator_smoke.exe")
set_tests_properties([=[agent_workflow_orchestrator_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6230;add_test;D:/rawrxd/CMakeLists.txt;0;")
add_test([=[RawrXD-GhostSoak]=] "D:/rawrxd/build-ninja/bin/RawrXD-GhostSoak.exe" "--iterations" "200" "--max-inflight" "16" "--timeout-ms" "1500")
set_tests_properties([=[RawrXD-GhostSoak]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;6257;add_test;D:/rawrxd/CMakeLists.txt;0;")
subdirs("src")
subdirs("src/reverse_engineering")
subdirs("src/tools/tokenizer_roundtrip_test")
subdirs("tests")
subdirs("src/tools")
