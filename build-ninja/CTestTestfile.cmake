# CMake generated Testfile for 
# Source directory: D:/rawrxd
# Build directory: D:/rawrxd/build-ninja
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[test_generation]=] "D:/rawrxd/build-ninja/bin/test_generation.exe")
set_tests_properties([=[test_generation]=] PROPERTIES  _BACKTRACE_TRIPLES "D:/rawrxd/CMakeLists.txt;7722;add_test;D:/rawrxd/CMakeLists.txt;0;")
subdirs("_deps/nlohmann_json-build")
subdirs("src/reverse_engineering")
subdirs("src/ceo")
subdirs("src/repository")
subdirs("src/generation")
subdirs("src/runtime")
subdirs("tests")
subdirs("src/tools")
subdirs("src/validation")
