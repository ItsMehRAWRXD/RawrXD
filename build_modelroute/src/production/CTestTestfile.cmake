# CMake generated Testfile for 
# Source directory: F:/rawrxd/src/production
# Build directory: F:/rawrxd/build_modelroute/src/production
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("rawrxd_production_hardening" "F:/rawrxd/build_modelroute/src/production/Debug/rawrxd_production_tests.exe")
  set_tests_properties("rawrxd_production_hardening" PROPERTIES  WORKING_DIRECTORY "F:/rawrxd/build_modelroute/src/production" _BACKTRACE_TRIPLES "F:/rawrxd/src/production/CMakeLists.txt;135;add_test;F:/rawrxd/src/production/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("rawrxd_production_hardening" "F:/rawrxd/build_modelroute/src/production/Release/rawrxd_production_tests.exe")
  set_tests_properties("rawrxd_production_hardening" PROPERTIES  WORKING_DIRECTORY "F:/rawrxd/build_modelroute/src/production" _BACKTRACE_TRIPLES "F:/rawrxd/src/production/CMakeLists.txt;135;add_test;F:/rawrxd/src/production/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("rawrxd_production_hardening" "F:/rawrxd/build_modelroute/src/production/MinSizeRel/rawrxd_production_tests.exe")
  set_tests_properties("rawrxd_production_hardening" PROPERTIES  WORKING_DIRECTORY "F:/rawrxd/build_modelroute/src/production" _BACKTRACE_TRIPLES "F:/rawrxd/src/production/CMakeLists.txt;135;add_test;F:/rawrxd/src/production/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("rawrxd_production_hardening" "F:/rawrxd/build_modelroute/src/production/RelWithDebInfo/rawrxd_production_tests.exe")
  set_tests_properties("rawrxd_production_hardening" PROPERTIES  WORKING_DIRECTORY "F:/rawrxd/build_modelroute/src/production" _BACKTRACE_TRIPLES "F:/rawrxd/src/production/CMakeLists.txt;135;add_test;F:/rawrxd/src/production/CMakeLists.txt;0;")
else()
  add_test("rawrxd_production_hardening" NOT_AVAILABLE)
endif()
