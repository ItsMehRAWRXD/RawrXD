# CMake generated Testfile for 
# Source directory: F:/rawrxd/tools/snap_process_guard
# Build directory: F:/rawrxd/build_qt_free/tools/snap_process_guard
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("snap_process_guard_test" "F:/rawrxd/build_qt_free/tools/snap_process_guard/Debug/snap_process_guard_cli.exe" "--help")
  set_tests_properties("snap_process_guard_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;39;add_test;F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("snap_process_guard_test" "F:/rawrxd/build_qt_free/tools/snap_process_guard/Release/snap_process_guard_cli.exe" "--help")
  set_tests_properties("snap_process_guard_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;39;add_test;F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("snap_process_guard_test" "F:/rawrxd/build_qt_free/tools/snap_process_guard/MinSizeRel/snap_process_guard_cli.exe" "--help")
  set_tests_properties("snap_process_guard_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;39;add_test;F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("snap_process_guard_test" "F:/rawrxd/build_qt_free/tools/snap_process_guard/RelWithDebInfo/snap_process_guard_cli.exe" "--help")
  set_tests_properties("snap_process_guard_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;39;add_test;F:/rawrxd/tools/snap_process_guard/CMakeLists.txt;0;")
else()
  add_test("snap_process_guard_test" NOT_AVAILABLE)
endif()
