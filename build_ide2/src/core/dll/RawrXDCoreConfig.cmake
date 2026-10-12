# RawrXDCoreConfig.cmake.in - CMake config for downstream consumers
# This file is configured by CMake and installed with the package


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was RawrXDCoreConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

include(CMakeFindDependencyMacro)

# Find dependencies
find_dependency(Threads REQUIRED)

# Import targets
include("${CMAKE_CURRENT_LIST_DIR}/RawrXDCoreTargets.cmake")

# Provide alias for easier use
if(TARGET RawrXD::RawrXDCore AND NOT TARGET RawrXDCore)
    add_library(RawrXDCore ALIAS RawrXD::RawrXDCore)
endif()

# Version check
set(RawrXDCore_VERSION )
set(RawrXDCore_VERSION_MAJOR 14)
set(RawrXDCore_VERSION_MINOR 7)
set(RawrXDCore_VERSION_PATCH 3)

# Provide include directory variable
set(RawrXDCore_INCLUDE_DIRS "")

# Provide library variable
set(RawrXDCore_LIBRARIES RawrXD::RawrXDCore)

# Provide definition for DLL import
if(WIN32)
    add_compile_definitions(RawrXDCore_EXPORTS=0)
endif()
