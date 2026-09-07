# Deep2 Gateway Runtime Certification — standalone island (no Ship, no C++23)
option(BUILD_DEEP2_GATEWAY_CERT_STANDALONE
  "Build Deep2_Gateway_Runtime_Certification (Win32-only)" ON)
if(NOT BUILD_DEEP2_GATEWAY_CERT_STANDALONE)
  return()
endif()

add_executable(Deep2_Gateway_Runtime_Certification
  ${CMAKE_SOURCE_DIR}/src/deep2/certification/Deep2_Cert_Main.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/certification/Deep2_Cert_MockGateway.cpp
)
target_include_directories(Deep2_Gateway_Runtime_Certification PRIVATE
  ${CMAKE_SOURCE_DIR}/src/deep2/certification)
target_compile_definitions(Deep2_Gateway_Runtime_Certification PRIVATE
  WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(Deep2_Gateway_Runtime_Certification PRIVATE
    /EHsc /GR- /W3 /std:c++20
    $<$<NOT:$<CONFIG:Debug>>:/O2>)
endif()
target_link_libraries(Deep2_Gateway_Runtime_Certification PRIVATE
  winhttp ws2_32)
set_target_properties(Deep2_Gateway_Runtime_Certification PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  OUTPUT_NAME Deep2_Gateway_Runtime_Certification
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
message(STATUS "[Deep2] Gateway cert island: Deep2_Gateway_Runtime_Certification")
