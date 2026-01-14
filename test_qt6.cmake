# Simple Qt6 test
set(Qt6_DIR "C:/Qt/6.7.3/msvc2022_64/lib/cmake/Qt6")
find_package(Qt6 REQUIRED COMPONENTS Core)

if(Qt6_FOUND)
    message(STATUS "Qt6 found: ${Qt6_VERSION}")
else()
    message(FATAL_ERROR "Qt6 NOT FOUND")
endif()