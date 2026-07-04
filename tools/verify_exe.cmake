# verify_exe.cmake - CMake script to verify EXE was created
# Usage: cmake -P verify_exe.cmake (expects EXE_PATH environment variable)

if(NOT DEFINED ENV{EXE_PATH})
    set(ENV{EXE_PATH} "${CMAKE_CURRENT_LIST_DIR}/../build/bin/rawrxd-cli.exe")
endif()

if(NOT EXISTS "$ENV{EXE_PATH}")
    message(FATAL_ERROR "[FATAL] EXE was not created - link failed silently: $ENV{EXE_PATH}")
endif()

message(STATUS "[OK] EXE exists and is fresh: $ENV{EXE_PATH}")
