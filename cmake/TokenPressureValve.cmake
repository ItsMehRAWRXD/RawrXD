# Additive: TOKEN_PRESSURE_VALVE_001 nozzle for RawrXD-Win32IDE.
# Orthogonal to ctx / temp / GPU split / model path.

option(RAWRXD_TOKEN_PRESSURE_VALVE
    "Link TOKEN_PRESSURE_VALVE_001 MASM nozzle into RawrXD-Win32IDE"
    ON)

function(rawrxd_apply_token_pressure_valve target_name)
    if(NOT RAWRXD_TOKEN_PRESSURE_VALVE)
        return()
    endif()
    if(NOT RAWR_HAS_MASM)
        message(WARNING "[TPV] RAWRXD_TOKEN_PRESSURE_VALVE=ON requires RAWR_HAS_MASM")
        return()
    endif()

    target_sources(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/TokenPressure_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/src/win32app/TokenPressure.cpp
    )
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/TokenPressure_x64.asm
        PROPERTIES LANGUAGE ASM_MASM
    )
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm
    )
    target_compile_definitions(${target_name} PRIVATE
        RAWRXD_TOKEN_PRESSURE_VALVE=1
    )
    message(STATUS "[TPV] TOKEN_PRESSURE_VALVE_001 enabled on ${target_name}")
endfunction()
