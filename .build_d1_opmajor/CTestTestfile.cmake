# CMake generated Testfile for 
# Source directory: F:/rawrxd/.worktrees/codex-d1-opmajor
# Build directory: F:/rawrxd/.build_d1_opmajor
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test("deep2_q5_0_parity" "F:/rawrxd/.build_d1_opmajor/deep2_q5_0_parity.exe")
set_tests_properties("deep2_q5_0_parity" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;2692;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("deep2_cpu_state_probe" "F:/rawrxd/.build_d1_opmajor/deep2_cpu_state_probe.exe")
set_tests_properties("deep2_cpu_state_probe" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;2714;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("deep2_h11_prefill_parity" "F:/rawrxd/.build_d1_opmajor/deep2_h11_prefill_parity.exe")
set_tests_properties("deep2_h11_prefill_parity" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;2753;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("q8k_edge_tests" "F:/rawrxd/.build_d1_opmajor/bin-msvc/q8k_edge_tests.exe")
set_tests_properties("q8k_edge_tests" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;4470;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("q8k_byte_parity" "F:/rawrxd/.build_d1_opmajor/bin-msvc/q8k_parity_tool.exe" "--blocks" "8" "--seed" "12345")
set_tests_properties("q8k_byte_parity" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;4471;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("quant_parity_cert" "F:/rawrxd/.build_d1_opmajor/bin-msvc/quant_parity_cert.exe" "--blocks" "8" "--seed" "12345")
set_tests_properties("quant_parity_cert" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;4472;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("kquant_dot_parity" "F:/rawrxd/.build_d1_opmajor/bin-msvc/kquant_dot_parity.exe")
set_tests_properties("kquant_dot_parity" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;4473;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
add_test("gate2_manifest_consistency" "C:/Program Files/CMake/bin/cmake.exe" "-E" "env" "POWERSHELL_TELEMETRY_OPTOUT=1" "powershell" "-ExecutionPolicy" "Bypass" "-NoProfile" "-File" "F:/rawrxd/.worktrees/codex-d1-opmajor/tools/gate2_manifest_consistency.ps1" "-BuildDir" "F:/rawrxd/.build_d1_opmajor")
set_tests_properties("gate2_manifest_consistency" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;4480;add_test;F:/rawrxd/.worktrees/codex-d1-opmajor/CMakeLists.txt;0;")
subdirs("3rdparty/ggml")
subdirs("tools/deep2_snap/deep2_snap")
subdirs("tools/snap_process_guard")
subdirs("tools/snap_supervisor")
subdirs("tools/deep2_debugger")
subdirs("tools/rawrxd_parity_final")
subdirs("src/production")
subdirs("src/workflow")
subdirs("tools/deep2_autotune")
subdirs("tools/agent_esp/rawrxd_agent_esp")
