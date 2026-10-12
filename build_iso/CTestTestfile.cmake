# CMake generated Testfile for 
# Source directory: F:/rawrxd/tests/agentic_resilience
# Build directory: F:/rawrxd/build_iso
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test("agentic-resilience" "F:/rawrxd/build_iso/agentic-resilience-tests.exe")
set_tests_properties("agentic-resilience" PROPERTIES  FAIL_REGULAR_EXPRESSION "SOME TESTS FAILED" PASS_REGULAR_EXPRESSION "ALL TESTS PASSED" TIMEOUT "300" _BACKTRACE_TRIPLES "F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;73;add_test;F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;0;")
add_test("hexmag-integration" "F:/rawrxd/build_iso/hexmag-integration-tests.exe")
set_tests_properties("hexmag-integration" PROPERTIES  FAIL_REGULAR_EXPRESSION "SOME TESTS FAILED" PASS_REGULAR_EXPRESSION "ALL TESTS PASSED" TIMEOUT "300" _BACKTRACE_TRIPLES "F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;91;add_test;F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;0;")
add_test("gguf-baseline-help" "C:/Program Files/CMake/bin/cmake.exe" "-E" "echo" "gguf_baseline: run with a real model.gguf path")
set_tests_properties("gguf-baseline-help" PROPERTIES  PASS_REGULAR_EXPRESSION "gguf_baseline" TIMEOUT "60" _BACKTRACE_TRIPLES "F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;117;add_test;F:/rawrxd/tests/agentic_resilience/CMakeLists.txt;0;")
