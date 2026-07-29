# CMakeLists.txt for Setup Wizard Component
# RawrXD IDE - Hardware Detection and Configuration Wizard

cmake_minimum_required(VERSION 3.16)


set(SETUP_WIZARD_SOURCES
    SetupWizard.cpp
)

set(SETUP_WIZARD_HEADERS
    SetupWizard.hpp
)

add_library(rawrxd_setup STATIC
    ${SETUP_WIZARD_SOURCES}
    ${SETUP_WIZARD_HEADERS}
)

<<<<<<< HEAD
# Qt-free: pure C++20
set_target_properties(rawrxd_setup PROPERTIES
=======
set_target_properties(rawrxd_setup PROPERTIES
    AUTOMOC ON
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(rawrxd_setup PUBLIC
)
<<<<<<< HEAD
if(WIN32)
    target_link_libraries(rawrxd_setup PRIVATE bcrypt)
endif()
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

target_include_directories(rawrxd_setup PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(rawrxd_setup PRIVATE
    RAWRXD_SETUP_WIZARD_ENABLED
)

message(STATUS "✓ Setup Wizard component configured")
