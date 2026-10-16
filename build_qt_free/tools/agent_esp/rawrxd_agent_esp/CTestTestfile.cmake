# CMake generated Testfile for 
# Source directory: F:/rawrxd/tools/agent_esp/rawrxd_agent_esp
# Build directory: F:/rawrxd/build_qt_free/tools/agent_esp/rawrxd_agent_esp
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("agent_esp_test" "F:/rawrxd/build_qt_free/tools/agent_esp/rawrxd_agent_esp/Debug/agent_esp_test.exe")
  set_tests_properties("agent_esp_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;11;add_test;F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("agent_esp_test" "F:/rawrxd/build_qt_free/tools/agent_esp/rawrxd_agent_esp/Release/agent_esp_test.exe")
  set_tests_properties("agent_esp_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;11;add_test;F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("agent_esp_test" "F:/rawrxd/build_qt_free/tools/agent_esp/rawrxd_agent_esp/MinSizeRel/agent_esp_test.exe")
  set_tests_properties("agent_esp_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;11;add_test;F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("agent_esp_test" "F:/rawrxd/build_qt_free/tools/agent_esp/rawrxd_agent_esp/RelWithDebInfo/agent_esp_test.exe")
  set_tests_properties("agent_esp_test" PROPERTIES  _BACKTRACE_TRIPLES "F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;11;add_test;F:/rawrxd/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt;0;")
else()
  add_test("agent_esp_test" NOT_AVAILABLE)
endif()
