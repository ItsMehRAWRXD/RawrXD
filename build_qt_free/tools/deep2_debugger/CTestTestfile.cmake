# CMake generated Testfile for 
# Source directory: F:/rawrxd/tools/deep2_debugger
# Build directory: F:/rawrxd/build_qt_free/tools/deep2_debugger
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("flight_recorder_smoke_test" "F:/rawrxd/build_qt_free/tools/deep2_debugger/Debug/flight_recorder_smoke.exe")
  set_tests_properties("flight_recorder_smoke_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;33;add_test;F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("flight_recorder_smoke_test" "F:/rawrxd/build_qt_free/tools/deep2_debugger/Release/flight_recorder_smoke.exe")
  set_tests_properties("flight_recorder_smoke_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;33;add_test;F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("flight_recorder_smoke_test" "F:/rawrxd/build_qt_free/tools/deep2_debugger/MinSizeRel/flight_recorder_smoke.exe")
  set_tests_properties("flight_recorder_smoke_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;33;add_test;F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("flight_recorder_smoke_test" "F:/rawrxd/build_qt_free/tools/deep2_debugger/RelWithDebInfo/flight_recorder_smoke.exe")
  set_tests_properties("flight_recorder_smoke_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;33;add_test;F:/rawrxd/tools/deep2_debugger/CMakeLists.txt;0;")
else()
  add_test("flight_recorder_smoke_test" NOT_AVAILABLE)
endif()
