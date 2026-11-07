# Standalone, local-only compiler/build/link toolchain facilities for
# the native Win32 IDE and model tool dispatch. No cloud inference dependency.
get_filename_component(_RAWR_TOOLCHAIN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(_RAWR_LINK_ROOT "${_RAWR_TOOLCHAIN_ROOT}/src/toolchain/linker")
if(EXISTS "${_RAWR_LINK_ROOT}/main.c" AND NOT TARGET RawrXD-PELinker)
    add_executable(RawrXD-PELinker
        "${_RAWR_LINK_ROOT}/main.c"
        "${_RAWR_LINK_ROOT}/coff_reader.c"
        "${_RAWR_LINK_ROOT}/section_merge.c"
        "${_RAWR_LINK_ROOT}/reloc_resolver.c"
        "${_RAWR_LINK_ROOT}/pe_writer.c"
        "${_RAWR_LINK_ROOT}/entry_stub.c")
    target_include_directories(RawrXD-PELinker PRIVATE "${_RAWR_LINK_ROOT}")
    set_target_properties(RawrXD-PELinker PROPERTIES OUTPUT_NAME rawrxd_link)
    add_executable(RawrXD-COFFCheck
        "${_RAWR_LINK_ROOT}/rawrxd_check.c"
        "${_RAWR_LINK_ROOT}/coff_reader.c")
    target_include_directories(RawrXD-COFFCheck PRIVATE "${_RAWR_LINK_ROOT}")
    set_target_properties(RawrXD-COFFCheck PROPERTIES OUTPUT_NAME rawrxd_check)
    install(TARGETS RawrXD-PELinker RawrXD-COFFCheck RUNTIME DESTINATION bin)
endif()

# Programmatic local tool interface for agents or the IDE process dispatcher.
# This is NOT registered as an auto-approved model tool: callers must explicitly
# request --approve-mutations before any build touches workspace files.
if(EXISTS "${_RAWR_TOOLCHAIN_ROOT}/tools/rawrxd_native_toolchain.py")
    install(PROGRAMS "${_RAWR_TOOLCHAIN_ROOT}/tools/rawrxd_native_toolchain.py"
            DESTINATION bin)
    # Required sibling module: without it, the packaged CLI fails at import.
    install(FILES "${_RAWR_TOOLCHAIN_ROOT}/tools/rawrxd_process_runner.py"
            DESTINATION bin)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND AND NOT TARGET RawrXD-NativeToolchain-Acceptance)
        add_custom_target(RawrXD-NativeToolchain-Acceptance
            COMMAND "${Python3_EXECUTABLE}" -m unittest discover
                -s "${_RAWR_TOOLCHAIN_ROOT}/tools/tests"
                -p test_native_toolchain.py -v
            WORKING_DIRECTORY "${_RAWR_TOOLCHAIN_ROOT}"
            COMMENT "Real, model-free compiler/build/link acceptance tests")
        add_custom_target(RawrXD-Subprocess-Acceptance
            COMMAND "${Python3_EXECUTABLE}" -m unittest discover
                -s "${_RAWR_TOOLCHAIN_ROOT}/tools/tests"
                -p test_process_runner.py -v
            WORKING_DIRECTORY "${_RAWR_TOOLCHAIN_ROOT}"
            COMMENT "Concurrent bounded subprocess pipes and timeout tree-kill gates")
    endif()
endif()
