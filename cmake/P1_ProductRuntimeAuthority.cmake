# Additive opt-in: P1_PRODUCT_RUNTIME_AUTHORITY MASM gate in RawrXD-Win32IDE only.
# Does not alter master_test_suite or other frozen certification targets.

option(RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    "Link P1_PRODUCT_RUNTIME_AUTHORITY MASM gate into RawrXD-Win32IDE (additive)"
    OFF)

function(rawrxd_apply_p1_product_runtime_authority target_name)
    if(NOT RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY)
        return()
    endif()
    if(NOT RAWR_HAS_MASM)
        message(WARNING "[P1PRA] RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY=ON requires RAWR_HAS_MASM")
        return()
    endif()

    target_sources(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/P1_ProductRuntimeAuthority_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/RawrXD_RuntimeAuthority_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/src/win32app/P1PRA_ProcessState.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/win32app/P1PRA_RuntimeAuthority.cpp
    )

    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/P1_ProductRuntimeAuthority_x64.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/RawrXD_RuntimeAuthority_x64.asm
        PROPERTIES LANGUAGE ASM_MASM
    )

    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asm
    )

    target_compile_definitions(${target_name} PRIVATE
        RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY=1
        P1PRA_SYMBOL_LINKED=1
    )

    target_compile_options(${target_name} PRIVATE
        "$<$<COMPILE_LANGUAGE:ASM_MASM>:/DRAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY=1>"
    )

    set(_p1pra_telemetry_asm ${CMAKE_SOURCE_DIR}/src/asm/RawrXD_Telemetry_Kernel.asm)
    set(_p1pra_witness_inc ${CMAKE_SOURCE_DIR}/src/asm/P1PRA_UtcWitness.inc)
    if(EXISTS ${_p1pra_telemetry_asm} AND EXISTS ${_p1pra_witness_inc})
        set_source_files_properties(${_p1pra_telemetry_asm} PROPERTIES
            OBJECT_DEPENDS "${_p1pra_witness_inc}")
    endif()

    if(MSVC)
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "P1PRA_SYMBOL_LINKED=1"
            COMMENT "[P1PRA] MASM authority linked into ${target_name}"
        )
    endif()

    message(STATUS "[P1PRA] Product runtime authority lane enabled on ${target_name}")
endfunction()
