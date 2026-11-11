cmake_minimum_required(VERSION 3.20)
project(RawrXD_Digestion VERSION 1.0.0 LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Core library
add_library(digestion_core STATIC
    digestion_reverse_engineering.cpp
    digestion_reverse_engineering.h
<<<<<<< HEAD
=======
    digestion_metrics.cpp
    digestion_metrics.h
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    digestion_config_manager.cpp
    digestion_config_manager.h
    digestion_db.cpp
    digestion_db.h
    digestion_orchestrator.cpp
    digestion_orchestrator.h
)

target_link_libraries(digestion_core PUBLIC
)

# ASM optimization module (Windows x64 only)
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    add_library(digestion_asm STATIC
        digestion_asm_x64.asm
        RawrXD_DigestionEngine.asm
    )
    target_link_libraries(digestion_core PRIVATE digestion_asm)
endif()

# CLI executable
add_executable(rxd-digest digestion_cli.cpp)
target_link_libraries(rxd-digest PRIVATE digestion_core)

<<<<<<< HEAD
# Win32 GUI executable (pure C++20, no Qt)
add_executable(rxd-digest-gui WIN32 main_gui.cpp digestion_gui_widget.cpp)
target_link_libraries(rxd-digest-gui PRIVATE digestion_core comctl32 shell32 ole32)

# Install
install(TARGETS rxd-digest rxd-digest-gui RUNTIME DESTINATION bin)
=======
# GUI executable (if Qt6 Widgets available)
if(Qt6Widgets_FOUND)
    add_executable(rxd-digest-gui 
        digestion_gui_widget.cpp
        digestion_gui_widget.h
        main_gui.cpp
    )
endif()

# Install
install(TARGETS rxd-digest RUNTIME DESTINATION bin)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
install(FILES digestion_reverse_engineering.h DESTINATION include)
install(FILES digestion_schema.sql DESTINATION share)

enable_testing()

add_executable(digestion_config_tests
    tests/digestion_config_tests.cpp
)
add_test(NAME digestion_config_tests COMMAND digestion_config_tests)

add_executable(digestion_db_tests
    tests/digestion_db_tests.cpp
)
add_test(NAME digestion_db_tests COMMAND digestion_db_tests)
