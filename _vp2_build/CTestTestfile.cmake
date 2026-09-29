# CMake generated Testfile for 
# Source directory: F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2
# Build directory: F:/~dev/_vp2_build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test("rawrxd-value-pack2-core" "F:/~dev/_vp2_build/Debug/rawrxd-value-pack2-test.exe")
  set_tests_properties("rawrxd-value-pack2-core" PROPERTIES  _BACKTRACE_TRIPLES "F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;27;add_test;F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test("rawrxd-value-pack2-core" "F:/~dev/_vp2_build/Release/rawrxd-value-pack2-test.exe")
  set_tests_properties("rawrxd-value-pack2-core" PROPERTIES  _BACKTRACE_TRIPLES "F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;27;add_test;F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test("rawrxd-value-pack2-core" "F:/~dev/_vp2_build/MinSizeRel/rawrxd-value-pack2-test.exe")
  set_tests_properties("rawrxd-value-pack2-core" PROPERTIES  _BACKTRACE_TRIPLES "F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;27;add_test;F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test("rawrxd-value-pack2-core" "F:/~dev/_vp2_build/RelWithDebInfo/rawrxd-value-pack2-test.exe")
  set_tests_properties("rawrxd-value-pack2-core" PROPERTIES  _BACKTRACE_TRIPLES "F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;27;add_test;F:/~dev/RawrXD_Value_Pack_2/RawrXD_Value_Pack_2/CMakeLists.txt;0;")
else()
  add_test("rawrxd-value-pack2-core" NOT_AVAILABLE)
endif()
