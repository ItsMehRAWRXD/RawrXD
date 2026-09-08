# Lavapath product — ChoreographOut + Produce1 + LavaPath (deep2 authority)
option(BUILD_DEEP2_PRODUCT_LAVAPATH "Build deep2_product_lavapath" ON)
if(BUILD_DEEP2_PRODUCT_LAVAPATH AND TARGET InferenceEngine)
  add_executable(deep2_product_lavapath
    ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/Deep2ProductLavapath.cpp
    ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/Deep2ProductLavapath_Ops.cpp)
  target_include_directories(deep2_product_lavapath PRIVATE
    ${CMAKE_SOURCE_DIR}/src/deep2/lavapath
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include)
  if(MSVC)
    target_compile_options(deep2_product_lavapath PRIVATE /EHsc /W3 /std:c++20)
  endif()
  target_link_libraries(deep2_product_lavapath PRIVATE InferenceEngine dxgi pdh psapi)
  set_target_properties(deep2_product_lavapath PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    OUTPUT_NAME deep2_product_lavapath
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  message(STATUS "[Product] lavapath: deep2_product_lavapath (ChoreographOut)")
endif()
