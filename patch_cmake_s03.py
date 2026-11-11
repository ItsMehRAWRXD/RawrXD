import io, os
P = r"F:\rawrxd\CMakeLists.txt"
with io.open(P, "r", encoding="utf-8", newline=None) as f:
    s = f.read()

anchor = "# N02 numerical correctness (tip Deep2Engine + real GGUF; CERTIFIED=0)."
block = '''if(EXISTS "${CMAKE_SOURCE_DIR}/tests/deep2_multitoken_decode_parity.cpp" AND TARGET deep2_engine_lib)
    add_executable(deep2_multitoken_decode_parity
        tests/deep2_multitoken_decode_parity.cpp)
    target_include_directories(deep2_multitoken_decode_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src/deep2 ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(deep2_multitoken_decode_parity PRIVATE deep2_engine_lib)
    target_compile_features(deep2_multitoken_decode_parity PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_multitoken_decode_parity PRIVATE /EHsc)
        target_compile_definitions(deep2_multitoken_decode_parity PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS)
    endif()
    set_target_properties(deep2_multitoken_decode_parity PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/$<CONFIG>")
    add_test(NAME deep2_multitoken_decode_parity
        COMMAND deep2_multitoken_decode_parity)
endif()

'''
if "deep2_multitoken_decode_parity.cpp" in s:
    raise SystemExit("target already present")
if s.count(anchor) != 1:
    raise SystemExit("CMake anchor not found exactly once")
s = s.replace(anchor, block + anchor, 1)
with io.open(P, "w", encoding="utf-8", newline="\r\n") as f:
    f.write(s)
print("added deep2_multitoken_decode_parity target")