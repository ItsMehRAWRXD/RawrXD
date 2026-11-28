# RawrXD portable install rules.
# Included from the top-level CMakeLists after all product targets are defined.
# No Qt, no external dependencies.

include(GNUInstallDirs)

set(RAWRXD_INSTALL_TARGETS "")
foreach(_rawrxd_target
    RawrXD-CLI-V2
    RawrXD-Win32IDE-Native
    deep2_engine_lib
    rawrxd_production_hardening
)
    if(TARGET ${_rawrxd_target})
        list(APPEND RAWRXD_INSTALL_TARGETS ${_rawrxd_target})
    endif()
endforeach()

if(RAWRXD_INSTALL_TARGETS)
    install(TARGETS ${RAWRXD_INSTALL_TARGETS}
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

# Portable runtime configuration template (never overwrite a user's file).
if(EXISTS "${CMAKE_SOURCE_DIR}/rawrxd.config.json")
    install(FILES "${CMAKE_SOURCE_DIR}/rawrxd.config.json"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/rawrxd"
        RENAME "rawrxd.config.template.json")
endif()

# Model registry and acquisition metadata.
if(EXISTS "${CMAKE_SOURCE_DIR}/models/registry.json")
    install(FILES "${CMAKE_SOURCE_DIR}/models/registry.json"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rawrxd/models")
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/models/acquisition.json")
    install(FILES "${CMAKE_SOURCE_DIR}/models/acquisition.json"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rawrxd/models")
endif()

# Required Vulkan shaders.
file(GLOB RAWRXD_INSTALL_SHADERS CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/deep2/shaders/*.spv")
if(RAWRXD_INSTALL_SHADERS)
    install(FILES ${RAWRXD_INSTALL_SHADERS}
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rawrxd/shaders")
endif()

# Version manifest.
if(EXISTS "${CMAKE_SOURCE_DIR}/VERSION")
    install(FILES "${CMAKE_SOURCE_DIR}/VERSION"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/rawrxd")
endif()

message(STATUS "RawrXD install rules loaded (${RAWRXD_INSTALL_TARGETS})")