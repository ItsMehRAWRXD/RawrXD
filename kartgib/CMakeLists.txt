cmake_minimum_required(VERSION 3.20)
project(KartGib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DNOMINMAX -D_WIN32_WINNT=0x0A00)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    add_compile_options(
        $<$<CONFIG:Debug>:/MDd>
        $<$<CONFIG:Release>:/MD>
        $<$<CONFIG:RelWithDebInfo>:/MD>
        $<$<CONFIG:MinSizeRel>:/MD>
    )
    add_compile_options(
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/GS>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:cf>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:ehcont>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/VOLATILE:ISO>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/W4>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/Zc:strictStrings>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/Zc:throwingNew>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/permissive->
    )
    add_link_options(
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/DYNAMICBASE>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/NXCOMPAT>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/HIGHENTROPYVA>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:cf>
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:ehcont>
    )
    add_compile_definitions(
        KARTGIB_HARDENING=1
        _FORTIFY_SOURCE=2
        FORTIFY_SOURCE=2
    )
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

find_package(Vulkan REQUIRED)

set(SOURCES
    src/main.cpp
    src/win32_window.cpp
    src/vulkan_renderer.cpp
    src/game_loop.cpp
    src/worldforge_bridge.cpp
    src/worldforge.cpp
    src/render_graph.cpp
    src/atmosphere_pipeline.cpp
    src/atmosphere_draw.cpp
    src/g04_copy.cpp
    src/g04_publish.cpp
    src/forensics_png.cpp
    src/forensics_report.cpp
    src/forensics_g05.cpp
    src/shadow_cascade.cpp
    src/shadow_resources.cpp
    src/shadow_pipeline.cpp
    src/shadow_draw.cpp
    src/shadow_cert.cpp
    src/chunk_grid.cpp
    src/chunk_stitch.cpp
    src/chunk_stream.cpp
    src/chunk_save.cpp
    src/chunk_tour.cpp
    src/finish_batches.cpp
    src/batch_world.cpp
    src/batch_climate.cpp
    src/batch_live.cpp
    src/batch_sim.cpp
    src/batch_play.cpp
    src/batch_audio.cpp
    src/batch_tools.cpp
    src/batch_ship.cpp
    src/ocean_fft.cpp
    src/ocean_spectrum.cpp
    src/ocean_field.cpp
    src/ocean_mesh.cpp
    src/ocean_cert.cpp
    src/ocean_gpu.cpp
    src/ocean_gpu_read.cpp
    src/ocean_tour.cpp
    src/terrain_cert.cpp
    src/product_geom.cpp
    src/product_inst.cpp
    src/product_net.cpp
    src/product_audio.cpp
    src/product_hash.cpp
    src/product_tour.cpp
    src/instance_pipe.cpp
    src/instance_draw.cpp
    src/instance_time.cpp
    src/editor_scene.cpp
    src/editor_file.cpp
    src/editor_view.cpp
    src/editor_input.cpp
    src/editor_mesh.cpp
    src/editor_shot.cpp
    src/editor_send.cpp
    src/editor_run.cpp
    src/editor_finish.cpp
    src/render_path.cpp
    src/studio_tape.cpp
    src/studio_brush.cpp
    src/studio_io.cpp
    src/studio_run.cpp
    src/inspector_wnd.cpp
    src/inspector_dock.cpp
    src/editor2_run.cpp
    src/inspector_cmd.cpp
    src/inspector_run.cpp
    src/inspector_late.cpp
    src/inspector_cap.cpp
    src/terrain_cursor.cpp
    src/terrain_field.cpp
    src/terrain_query.cpp
    src/terrain_io.cpp
    src/terrain_pick.cpp
    src/terrain_input.cpp
)

add_executable(TerrainStudioCert
    src/terrain_studio_cert.cpp
    src/terrain_field.cpp
    src/terrain_query.cpp
    src/terrain_io.cpp
    src/terrain_pick.cpp
)

set(SHADERS
    shaders/terrain.vert
    shaders/terrain.frag
    shaders/debug_triangle.vert
    shaders/debug_triangle.frag
)

add_executable(KartGib ${SOURCES} ${SHADERS})

target_link_libraries(KartGib PRIVATE Vulkan::Vulkan ${CMAKE_DL_LIBS})

find_program(GLSLC glslc HINTS "$ENV{VULKAN_SDK}/Bin" "$ENV{VULKAN_SDK}/bin")
if(GLSLC)
    file(GLOB SHADER_SOURCES ${CMAKE_SOURCE_DIR}/shaders/*.vert ${CMAKE_SOURCE_DIR}/shaders/*.frag ${CMAKE_SOURCE_DIR}/shaders/*.comp)
    foreach(SHADER ${SHADER_SOURCES})
        get_filename_component(SPV_NAME ${SHADER} NAME)
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/shaders/${SPV_NAME}.spv
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/shaders
            COMMAND ${GLSLC} ${SHADER} -o ${CMAKE_CURRENT_BINARY_DIR}/shaders/${SPV_NAME}.spv
            DEPENDS ${SHADER}
            VERBATIM
        )
        list(APPEND SHADER_SPVS ${CMAKE_CURRENT_BINARY_DIR}/shaders/${SPV_NAME}.spv)
    endforeach()
    add_custom_target(kartgib_shaders DEPENDS ${SHADER_SPVS})
    add_dependencies(KartGib kartgib_shaders)
endif()

add_custom_command(TARGET KartGib POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:KartGib>/shaders
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/shaders
        $<TARGET_FILE_DIR:KartGib>/shaders
    COMMENT "Copying compiled shaders to executable directory"
)
