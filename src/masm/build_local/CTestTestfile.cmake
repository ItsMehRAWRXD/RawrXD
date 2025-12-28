# CMake generated Testfile for 
# Source directory: C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm
# Build directory: C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/build_local
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test([=[MASM_HotpatchSuite]=] "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/build_local/bin/tests/Debug/masm_hotpatch_test.exe")
  set_tests_properties([=[MASM_HotpatchSuite]=] PROPERTIES  FAIL_REGULAR_EXPRESSION "\\[FAIL\\]" PASS_REGULAR_EXPRESSION "Test Summary" _BACKTRACE_TRIPLES "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;131;add_test;C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test([=[MASM_HotpatchSuite]=] "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/build_local/bin/tests/Release/masm_hotpatch_test.exe")
  set_tests_properties([=[MASM_HotpatchSuite]=] PROPERTIES  FAIL_REGULAR_EXPRESSION "\\[FAIL\\]" PASS_REGULAR_EXPRESSION "Test Summary" _BACKTRACE_TRIPLES "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;131;add_test;C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test([=[MASM_HotpatchSuite]=] "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/build_local/bin/tests/MinSizeRel/masm_hotpatch_test.exe")
  set_tests_properties([=[MASM_HotpatchSuite]=] PROPERTIES  FAIL_REGULAR_EXPRESSION "\\[FAIL\\]" PASS_REGULAR_EXPRESSION "Test Summary" _BACKTRACE_TRIPLES "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;131;add_test;C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test([=[MASM_HotpatchSuite]=] "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/build_local/bin/tests/RelWithDebInfo/masm_hotpatch_test.exe")
  set_tests_properties([=[MASM_HotpatchSuite]=] PROPERTIES  FAIL_REGULAR_EXPRESSION "\\[FAIL\\]" PASS_REGULAR_EXPRESSION "Test Summary" _BACKTRACE_TRIPLES "C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;131;add_test;C:/Users/HiH8e/Downloads/RawrXD-production-lazy-init/src/masm/CMakeLists.txt;0;")
else()
  add_test([=[MASM_HotpatchSuite]=] NOT_AVAILABLE)
endif()
