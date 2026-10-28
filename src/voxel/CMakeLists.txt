# ============================================================================
# The native voxel renderer.
#
# This builds on its own, so that the engine can be built and run without
# the rest of the tree:
#
#   cmake -S src/voxel -B build/voxel -G "Visual Studio 17 2022" -A x64
#   cmake --build build/voxel --config Release
#
# The top level of the tree includes it as well, so that the voxel engine
# is part of the ordinary build.
#
# Nothing here is third-party. The renderer is Direct3D 12 from the
# Windows SDK, the browser is WebView2 from the Windows SDK, and the
# whole of the engine is the sources in this folder.
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# The target is built on its own as well as as part of the tree, so the
# project is only declared when this is the top of the build.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(sunshine_voxel LANGUAGES CXX)
    set(SUNSHINE_VOXEL_STANDALONE ON)
else()
    set(SUNSHINE_VOXEL_STANDALONE OFF)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3 /permissive- /EHsc /utf-8)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
endif()

# The repository root, which holds the WebView2 declarations.
get_filename_component(RAWRXD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

add_executable(sunshine-voxel
    main.cpp
    ChunkStore.cpp
    RuinBuilder.cpp
    GreedyMesher.cpp
    VoxelRenderer.cpp
    FrameCapture.cpp
    BrowserPanel.cpp
)

target_include_directories(sunshine-voxel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${RAWRXD_ROOT}/include
)

# The Direct3D rules the renderer depends on, checked instead of
# remembered. Every one of them was found by a failure.
add_executable(sunshine-voxel-d3d12-tests
    voxel_d3d12_tests.cpp
)
target_include_directories(sunshine-voxel-d3d12-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(sunshine-voxel-d3d12-tests PRIVATE d3d12 dxgi d3dcompiler)
set_target_properties(sunshine-voxel-d3d12-tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# The gates of a conifer. A tree is not certified because it looks like
# one; it is certified because its silhouette has a trunk, tiers, and a
# crown that narrows to the point.
add_executable(sunshine-voxel-tree-tests
    voxel_tree_tests.cpp
    ChunkStore.cpp
    RuinBuilder.cpp
)
target_include_directories(sunshine-voxel-tree-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(sunshine-voxel-tree-tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# The gates of a gothic ruin. The ruin is certified by its silhouette
# and by its openings, not by how it looks.
add_executable(sunshine-voxel-ruin-tests
    voxel_ruin_tests.cpp
    RuinBuilder.cpp
)

target_include_directories(sunshine-voxel-ruin-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(sunshine-voxel-ruin-tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# The Direct3D 12 headers come with the Windows SDK, and the libraries
# with it too.
target_link_libraries(sunshine-voxel PRIVATE
    d3d12
    dxgi
    dxguid
    d3dcompiler
    user32
    gdi32
    ole32
    uuid
    shlwapi
)

# The page and the browser loader sit next to the executable, because the
# engine looks for them there.
set(SUNSHINE_VOXEL_ASSETS
    ${CMAKE_CURRENT_SOURCE_DIR}/voxel_page.html
    ${RAWRXD_ROOT}/Ship/webview2/build/native/x64/WebView2Loader.dll
)

foreach(asset IN LISTS SUNSHINE_VOXEL_ASSETS)
    if(EXISTS ${asset})
        add_custom_command(TARGET sunshine-voxel POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${asset}" "$<TARGET_FILE_DIR:sunshine-voxel>"
            COMMENT "Copying ${asset} next to the executable")
    else()
        message(STATUS "sunshine-voxel: ${asset} was not found and will not be copied")
    endif()
endforeach()
