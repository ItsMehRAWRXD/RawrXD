# RawrXD-Script Tests

# Test executable
add_executable(script_tests test_main.cpp)

target_link_libraries(script_tests PRIVATE rawrxd-js)

# Add tests
add_test(NAME ScriptTests COMMAND script_tests)

# Sample JS files for testing
set(TEST_JS_FILES
    test_basic.js
    test_functions.js
    test_control_flow.js
    test_objects.js
)

foreach(js_file ${TEST_JS_FILES})
    configure_file(${js_file} ${CMAKE_CURRENT_BINARY_DIR}/${js_file} COPYONLY)
endforeach()
