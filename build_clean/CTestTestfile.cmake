# CMake generated Testfile for 
# Source directory: F:/rawrxd
# Build directory: F:/rawrxd/build_clean
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("agentic-resilience" "F:/rawrxd/build_clean/Debug/agentic-resilience-tests.exe")
  set_tests_properties("agentic-resilience" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/CMakeLists.txt;2443;add_test;F:/rawrxd/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("agentic-resilience" "F:/rawrxd/build_clean/Release/agentic-resilience-tests.exe")
  set_tests_properties("agentic-resilience" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/CMakeLists.txt;2443;add_test;F:/rawrxd/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("agentic-resilience" "F:/rawrxd/build_clean/MinSizeRel/agentic-resilience-tests.exe")
  set_tests_properties("agentic-resilience" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/CMakeLists.txt;2443;add_test;F:/rawrxd/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("agentic-resilience" "F:/rawrxd/build_clean/RelWithDebInfo/agentic-resilience-tests.exe")
  set_tests_properties("agentic-resilience" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/CMakeLists.txt;2443;add_test;F:/rawrxd/CMakeLists.txt;0;")
else()
  add_test("agentic-resilience" NOT_AVAILABLE)
endif()
subdirs("_deps/zlib-build")
subdirs("3rdparty/ggml")
subdirs("src/workflow")
