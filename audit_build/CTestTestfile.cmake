# CMake generated Testfile for 
# Source directory: D:/rawrxd
# Build directory: D:/rawrxd/audit_build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[test_generation]=] "D:/rawrxd/audit_build/bin/test_generation.exe")
set_tests_properties([=[test_generation]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;7490;add_test;D:/rawrxd/CMakeLists.txt;0;")
subdirs("src/reverse_engineering")
subdirs("src/ceo")
subdirs("src/repository")
subdirs("src/generation")
subdirs("tests")
subdirs("src/tools")
subdirs("src/validation")
