# CMake generated Testfile for 
# Source directory: F:/rawrxd/tools/deep2_snap/deep2_snap
# Build directory: F:/rawrxd/build_qt_free/tools/deep2_snap/deep2_snap
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("deep2_snap_test" "F:/rawrxd/build_qt_free/tools/deep2_snap/deep2_snap/Debug/deep2_snap_test.exe")
  set_tests_properties("deep2_snap_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;9;add_test;F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("deep2_snap_test" "F:/rawrxd/build_qt_free/tools/deep2_snap/deep2_snap/Release/deep2_snap_test.exe")
  set_tests_properties("deep2_snap_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;9;add_test;F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("deep2_snap_test" "F:/rawrxd/build_qt_free/tools/deep2_snap/deep2_snap/MinSizeRel/deep2_snap_test.exe")
  set_tests_properties("deep2_snap_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;9;add_test;F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("deep2_snap_test" "F:/rawrxd/build_qt_free/tools/deep2_snap/deep2_snap/RelWithDebInfo/deep2_snap_test.exe")
  set_tests_properties("deep2_snap_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;9;add_test;F:/rawrxd/tools/deep2_snap/deep2_snap/CMakeLists.txt;0;")
else()
  add_test("deep2_snap_test" NOT_AVAILABLE)
endif()
