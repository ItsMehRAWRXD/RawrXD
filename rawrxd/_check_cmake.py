import sys, os

raw = open('CMakeLists.txt', 'rb').read()
nulls = raw.count(b'\x00')
print(f'bytes={len(raw)} nulls={nulls}')

if nulls > 0:
    # Truncate at first null — everything after is UTF-16 garbage
    idx = raw.find(b'\x00')
    raw = raw[:idx]
    open('CMakeLists.txt', 'wb').write(raw)
    print(f'stripped to {len(raw)} bytes')

text = raw.decode('utf-8')
lines = text.splitlines()
print(f'lines={len(lines)}')
print(f'last line: {repr(lines[-1][:80])}')

# Check if target already present
if 'test_device_fault_recovery' in text:
    print('target already present — nothing to do')
    sys.exit(0)

addition = """
# ============================================================================
# weight_projection + test_device_fault_recovery
# ============================================================================
if(Vulkan_FOUND)

add_executable(test_device_fault_recovery
    tests/test_device_fault_recovery.cpp
    src/deep2/weight_projection.cpp
    src/deep2/vulkan_compute.cpp
    src/deep2/GGUFLoader.cpp
    src/deep2/Deep2Engine.cpp
    src/deep2/QuantKernelRegistry.cpp
    src/deep2/ThreadPool.cpp
    src/deep2/KVCache.cpp
    src/deep2/MoERouter.cpp
    src/deep2/MoEWeightProxy.cpp
    src/deep2/MoEEliminate.cpp
    src/deep2/MoEWeightsLoader.cpp
    src/deep2/MoEArchitectureParser.cpp
    src/deep2/K2GlobalTensorIndex.cpp
    src/deep2/ResidencyManager.cpp
    src/deep2/HotPatcher.cpp
    src/deep2/HotPatcherSafety.cpp
    src/deep2/MASMKernelStubs.cpp
    src/deep2/sovereign_q4k_gemv.asm
    src/deep2/sovereign_deep2_kernels.asm
    tests/deep2_link_stubs.cpp
)

target_include_directories(test_device_fault_recovery PRIVATE
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${Vulkan_INCLUDE_DIRS}
)

target_link_libraries(test_device_fault_recovery PRIVATE Vulkan::Vulkan)

if(MSVC)
    target_compile_options(test_device_fault_recovery PRIVATE /arch:AVX512 /O2 /EHsc)
    target_compile_definitions(test_device_fault_recovery PRIVATE RAWRXD_HAS_AVX512=1 VK_USE_PLATFORM_WIN32_KHR)
else()
    target_compile_options(test_device_fault_recovery PRIVATE -mavx512f -mavx512vl -O3)
    target_compile_definitions(test_device_fault_recovery PRIVATE RAWRXD_HAS_AVX512=1)
endif()

set_target_properties(test_device_fault_recovery PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

endif() # Vulkan_FOUND
"""

with open('CMakeLists.txt', 'a', encoding='utf-8', newline='\n') as f:
    f.write(addition)

# Verify
text2 = open('CMakeLists.txt', encoding='utf-8').read()
if 'test_device_fault_recovery' in text2:
    print('APPENDED OK')
else:
    print('APPEND FAILED')
