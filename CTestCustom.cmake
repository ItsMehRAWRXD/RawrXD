# CTest customization — auto-cap output and clean test-harness temp files.
# Placed at project root so ctest picks it up when run from any build dir.

# Cap test output to 10 MB per test (passed or failed) to prevent runaway logs.
set(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 10240000)
set(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 10240000)

# Clean test-harness temporary directory before and after each test run.
# CTest creates Testing/Temporary for vstest/ctest internal use; leftover
# LastTest.log.tmp* files can grow unbounded (observed 88 GB in one case).
if(WIN32)
    # Windows: use cmd /c rmdir /s /q for reliable recursive delete
    set(CTEST_CUSTOM_PRE_TEST "cmd /c if exist Testing\\Temporary rmdir /s /q Testing\\Temporary")
    set(CTEST_CUSTOM_POST_TEST "cmd /c if exist Testing\\Temporary rmdir /s /q Testing\\Temporary")
else()
    # Unix-like
    set(CTEST_CUSTOM_PRE_TEST "rm -rf Testing/Temporary")
    set(CTEST_CUSTOM_POST_TEST "rm -rf Testing/Temporary")
endif()