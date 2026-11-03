# CMake generated Testfile for 
# Source directory: F:/rawrxd/tools/rawrxd_parity_final
# Build directory: F:/rawrxd/build_ghosttext_boundary/tools/rawrxd_parity_final
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test("rawr_run_self_test" "F:/rawrxd/build_ghosttext_boundary/tools/rawrxd_parity_final/rawr_run.exe" "--self-test")
set_tests_properties("rawr_run_self_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/rawrxd_parity_final/CMakeLists.txt;84;add_test;F:/rawrxd/tools/rawrxd_parity_final/CMakeLists.txt;0;")
add_test("rawr_fuzz_parsers" "F:/rawrxd/build_ghosttext_boundary/tools/rawrxd_parity_final/rawr_fuzz_parsers.exe" "20000")
set_tests_properties("rawr_fuzz_parsers" PROPERTIES  TIMEOUT "120" _BACKTRACE_TRIPLES "F:/rawrxd/tools/rawrxd_parity_final/CMakeLists.txt;146;add_test;F:/rawrxd/tools/rawrxd_parity_final/CMakeLists.txt;0;")
