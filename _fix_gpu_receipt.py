import re

p = r'F:\~dev\rawrxd\src\win32app\main_win32.cpp'
t = open(p, 'r', encoding='utf-8', errors='replace').read()

# Find the receipt block starting with f << "=== RAWRXD_GPU and ending with f.close();
old = re.search(r'f << "=== RAWRXD_GPU.*?f\.close\(\);', t, re.DOTALL)
if old:
    old_block = old.group(0)
    new_lines = [
        'std::fprintf(f, "=== RAWRXD_GPU_CORRECTNESS_001 ===\\n");',
        'std::fprintf(f, "MODEL_PATH=%s\\n", modelPath.c_str());',
        'std::fprintf(f, "VULKAN_INIT=%s\\n", vulkanInit.c_str());',
        'std::fprintf(f, "DEVICE_COUNT=%d\\n", deviceCount);',
        'std::fprintf(f, "SELECTED_DEVICE=%s\\n", selectedDevice.c_str());',
        'std::fprintf(f, "SELECTED_VENDOR=%s\\n", selectedVendor.c_str());',
        'std::fprintf(f, "SELECTED_DEVICE_ID=%s\\n", selectedDeviceId.c_str());',
        'std::fprintf(f, "\\n");',
        'std::fprintf(f, "MODEL_LOAD=%s\\n", modelLoad.c_str());',
        'std::fprintf(f, "GPU_FORWARD_REQUESTED=%d\\n", gpuForwardRequested);',
        'std::fprintf(f, "GPU_FORWARD_REACHED=%d\\n", gpuForwardReached);',
        'std::fprintf(f, "GPU_DISPATCH_COUNT=%d\\n", gpuDispatchCount);',
        'std::fprintf(f, "\\n");',
        'std::fprintf(f, "LOGITS_COUNT=%d\\n", logitsCount);',
        'std::fprintf(f, "LOGITS_FINITE=%d\\n", logitsFinite);',
        'std::fprintf(f, "LOGITS_NAN=%d\\n", logitsNan);',
        'std::fprintf(f, "LOGITS_INF=%d\\n", logitsInf);',
        'std::fprintf(f, "\\n");',
        'std::fprintf(f, "GENERATED_TOKEN_COUNT=%d\\n", generatedTokenCount);',
        'std::fprintf(f, "GENERATION_STATUS=%s\\n", generationStatus.c_str());',
        'std::fprintf(f, "\\n");',
        'std::fprintf(f, "HOST_FALLBACKS=%d\\n", hostFallbacks);',
        'std::fprintf(f, "UNPLANNED_FALLBACKS=%d\\n", unplannedFallbacks);',
        'std::fprintf(f, "STRICT_GPU_VIOLATIONS=%d\\n", strictGpuViolations);',
        'std::fprintf(f, "STUB_FALLBACKS=%d\\n", stubFallbacks);',
        'std::fprintf(f, "TEST_BACKEND_USED=%d\\n", testBackendUsed);',
        'std::fprintf(f, "\\n");',
        'std::fprintf(f, "VERDICT=%s\\n", pass ? "PASS" : "FAIL");',
        'std::fprintf(f, "=== RECEIPT_END ===\\n");',
        'std::fclose(f);'
    ]
    # Preserve leading whitespace from the first line of old_block
    leading = ''
    for c in old_block:
        if c in ' \t':
            leading += c
        else:
            break
    new_block = '\n'.join(leading + l for l in new_lines)
    t2 = t.replace(old_block, new_block)
    if t2 != t:
        open(p, 'w', encoding='utf-8').write(t2)
        print('REPLACED successfully')
    else:
        print('REPLACE FAILED (no change)')
else:
    print('NOT FOUND - searching for pattern...')
    # Try a simpler search
    if 'RAWRXD_GPU_CORRECTNESS_001' in t:
        print('Found RAWRXD_GPU_CORRECTNESS_001 in file')
    if 'f.close();' in t:
        print('Found f.close() in file')
    if 'ofstream' in t:
        print('Found ofstream in file')