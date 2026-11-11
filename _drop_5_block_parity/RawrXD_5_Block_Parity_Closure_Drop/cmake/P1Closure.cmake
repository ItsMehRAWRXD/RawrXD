# RawrXD P1 source-inventory closure helpers.
# No external dependencies.

function(rawrxd_p1_filter_source_list list_name manifest_path)
    if(NOT DEFINED ${list_name})
        message(FATAL_ERROR "[P1] source list not defined: ${list_name}")
    endif()

    set(_present "")
    set(_missing "")

    foreach(_src IN LISTS ${list_name})
        if(IS_ABSOLUTE "${_src}")
            set(_probe "${_src}")
        else()
            set(_probe "${CMAKE_SOURCE_DIR}/${_src}")
        endif()

        if(EXISTS "${_probe}")
            list(APPEND _present "${_src}")
        else()
            list(APPEND _missing "${_src}")
            message(STATUS "[P1][${list_name}][SKIP_MISSING] ${_src}")
        endif()
    endforeach()

    list(REMOVE_DUPLICATES _present)
    list(REMOVE_DUPLICATES _missing)

    list(LENGTH _present _present_count)
    list(LENGTH _missing _missing_count)

    get_filename_component(_manifest_dir "${manifest_path}" DIRECTORY)
    file(MAKE_DIRECTORY "${_manifest_dir}")

    file(WRITE "${manifest_path}"
        "P1_SOURCE_FILTER\n"
        "list=${list_name}\n"
        "present=${_present_count}\n"
        "missing=${_missing_count}\n"
        "missing_begin\n")

    foreach(_src IN LISTS _missing)
        file(APPEND "${manifest_path}" "${_src}\n")
    endforeach()
    file(APPEND "${manifest_path}" "missing_end\n")

    message(STATUS
        "[P1][${list_name}] present=${_present_count} missing=${_missing_count}")

    set(${list_name} "${_present}" PARENT_SCOPE)
    set(P1_${list_name}_PRESENT_COUNT "${_present_count}" PARENT_SCOPE)
    set(P1_${list_name}_MISSING_COUNT "${_missing_count}" PARENT_SCOPE)
    set(P1_${list_name}_MISSING "${_missing}" PARENT_SCOPE)
endfunction()

function(rawrxd_p1_assert_required_hexmag)
    set(_required
        src/win32app/Win32IDE_HexMag.cpp
        src/core/hexmag_control_plane.cpp
        src/core/hexmag_oracle_binder.cpp
        src/core/hexmag_runtime_controller.cpp
        src/core/hexmag_ide_link_probe.cpp
        src/agent/hexmag_client.cpp
    )

    foreach(_src IN LISTS _required)
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_src}")
            message(FATAL_ERROR
                "[P1][HexMag] required promoted source missing: ${_src}")
        endif()
    endforeach()

    if(RAWR_HAS_MASM)
        foreach(_src
            src/asm/RawrXD_HexMag_Swarm.asm
            src/asm/RawrXD_HexMag_RepeatTuner.asm)
            if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_src}")
                message(FATAL_ERROR
                    "[P1][HexMag] required MASM source missing: ${_src}")
            endif()
        endforeach()
    endif()

    message(STATUS "[P1][HexMag] required promoted sources present")
endfunction()
