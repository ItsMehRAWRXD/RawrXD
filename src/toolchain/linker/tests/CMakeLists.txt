# Executable end-to-end PE/COFF linker tests; never a placeholder PASS.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME rawrxd-linker-native-coff-to-pe
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_native_linker.py"
      --linker "$<TARGET_FILE:rawrxd_link>"
      --checker "$<TARGET_FILE:rawrxd_check>")
set_tests_properties(rawrxd-linker-native-coff-to-pe PROPERTIES TIMEOUT 180)
