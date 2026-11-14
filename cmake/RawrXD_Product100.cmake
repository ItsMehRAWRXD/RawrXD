# Include from the root CMakeLists.txt after RawrXD-Win32IDE exists:
#
#   include(cmake/RawrXD_Product100.cmake)
#
# If your tree uses a dedicated MASM object library, move
# src/asm/RawrXD_Product100_x64.asm into that target and keep the C++ file here.

if(TARGET RawrXD-Win32IDE)
  target_sources(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/RawrXD_Product100.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wave3.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wave4.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_Product100_x64.asm
    ${CMAKE_CURRENT_LIST_DIR}/../src/product/gateway/product_deep2_infer.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/product/gateway/product_deep2_infer_seh.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/deep2/lavapath/ProductRunDecode.cpp
  )
  target_include_directories(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
  )
  target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWRXD_PRODUCT100=1)
  # ProductRunDecode must win RunDecodeStream under /FORCE:MULTIPLE (LNK4006).
  target_link_options(RawrXD-Win32IDE PRIVATE
    "/INCLUDE:?RunDecodeStream@product_run@rawr@@YAXAEAUProductRuntime@12@PEBDIAEBV?$function@$$A6A_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z@std@@AEAUResult@12@AEAH@Z")
  set_source_files_properties(
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_Product100_x64.asm
    PROPERTIES LANGUAGE ASM_MASM)
  message(STATUS "[Win32IDE] Product100 overlay linked (RAWRXD_PRODUCT100=1)")
else()
  message(FATAL_ERROR "RawrXD_Product100.cmake must be included after RawrXD-Win32IDE target is declared")
endif()

