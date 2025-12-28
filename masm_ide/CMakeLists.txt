cmake_minimum_required(VERSION 3.16)
project(MASM_IDE_Complete)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Qt configuration
set(CMAKE_PREFIX_PATH "C:/Qt/6.7.3/msvc2022_64")
find_package(Qt6 COMPONENTS Core Gui Widgets Network REQUIRED)

# ============================================================================
# C++ Component Library (from RawrXD-ModelLoader)
# ============================================================================

add_subdirectory(components)

# ============================================================================
# Amazon Q Plugin (existing)
# ============================================================================

add_subdirectory(plugins/amazonq)

# ============================================================================
# Main MASM IDE Application
# ============================================================================

add_executable(MASM_IDE
    # Add your existing MASM IDE sources here
    # main.cpp
    # mainwindow.cpp
    # etc.
)

target_link_libraries(MASM_IDE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    masm_components  # Link the new C++ components
    AmazonQPlugin    # Existing plugin
)

target_include_directories(MASM_IDE PRIVATE
    components/include
    plugins/amazonq
)
