@echo off
setlocal enabledelayedexpansion

powershell -Command "
$content = [IO.File]::ReadAllText('F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp')

# Fix 1: Update call site to pass liveTypeMap_
$content = $content.Replace('reconstructedKv = ExecuteMLADecompressForward(inputView, *kvANormView, *kvAMqaView, *kvBView);', 'reconstructedKv = ExecuteMLADecompressForward(inputView, *kvANormView, *kvAMqaView, *kvBView, liveTypeMap_);')

# Fix 2: Fix DequantizeTensor calls in MLA function
$content = $content.Replace('DequantizeTensor(kvANorm, kvANormW);', 'DequantizeTensor(kvANorm, kvANormW, liveTypeMap);')
$content = $content.Replace('DequantizeTensor(kvAMqa, kvAMqaW);', 'DequantizeTensor(kvAMqa, kvAMqaW, liveTypeMap);')
$content = $content.Replace('DequantizeTensor(kvB, kvBW);', 'DequantizeTensor(kvB, kvBW, liveTypeMap);')

# Fix 3: Remove duplicate declarations in MLA function
# Find the duplicate block
$old1 = '    // Split aOut into compressed KV (512) and key rope (64)' + [Environment]::NewLine + '    const uint32_t kvRank = Generated::ModelConfig::kKvLoraRank;' + [Environment]::NewLine + '    const uint32_t ropeDim = Generated::ModelConfig::kRopeDimensionCount;' + [Environment]::NewLine + [Environment]::NewLine + '    std::vector<float> compressedKV(aOut.begin(), aOut.begin() + kvRank);' + [Environment]::NewLine + '    std::vector<float> keyRope(aOut.begin() + kvRank, aOut.end());'
$new1 = '    // Split aOut into compressed KV (512) and key rope (64)' + [Environment]::NewLine + '    std::vector<float> compressedKV(aOut.begin(), aOut.begin() + kvRank);' + [Environment]::NewLine + '    std::vector<float> keyRope(aOut.begin() + kvRank, aOut.end());'

$old2 = '    // Step 4: Pack expanded (4096) into MLA heads (16 x 320 = 5120)' + [Environment]::NewLine + '    // Per head: 128 K-nope + 64 K-rope + 128 V = 320' + [Environment]::NewLine + '    const uint32_t keyNopeDim = keyDim - ropeDim; // 128' + [Environment]::NewLine + '    const uint32_t perHead = keyDim + valueDim;   // 320'
$new2 = '    // Step 4: Pack expanded (4096) into MLA heads (16 x 320 = 5120)' + [Environment]::NewLine + '    // Per head: 128 K-nope + 64 K-rope + 128 V = 320'

$old3 = '    const uint32_t expandedDim = kvB.dims[1];  // 4096' + [Environment]::NewLine + '    if (expandedDim != heads * (keyDim - ropeDim + valueDim)) {' + [Environment]::NewLine + '        std::fprintf(stderr, \"[IR][MLA] kv_b output dim=%u mismatch\n\", expandedDim);' + [Environment]::NewLine + '        fflush(stderr);' + [Environment]::NewLine + '        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);' + [Environment]::NewLine + '    }'
$new3 = '    if (expandedDim != heads * (keyDim - ropeDim + valueDim)) {' + [Environment]::NewLine + '        std::fprintf(stderr, \"[IR][MLA] kv_b output dim=%u mismatch\n\", expandedDim);' + [Environment]::NewLine + '        fflush(stderr);' + [Environment]::NewLine + '        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);' + [Environment]::NewLine + '    }'

$old4 = '    const uint32_t keyNopeDim = keyDim - ropeDim; // 128' + [Environment]::NewLine + '    const uint32_t perHead = keyDim + valueDim;   // 320' + [Environment]::NewLine + [Environment]::NewLine + '    std::vector<float> mla(size_t(heads) * perHead, 0.0f);'
$new4 = '    std::vector<float> mla(size_t(heads) * perHead, 0.0f);'

$content = $content.Replace($old1, $new1)
$content = $content.Replace($old2, $new2)
$content = $content.Replace($old3, $new3)
$content = $content.Replace($old4, $new4)

# Fix 4: Update call site
$content = $content.Replace('reconstructedKv = ExecuteMLADecompressForward(inputView, *kvANormView, *kvAMqaView, *kvBView);', 'reconstructedKv = ExecuteMLADecompressForward(inputView, *kvANormView, *kvAMqaView, *kvBView, liveTypeMap_);')

# Fix 5: Update DequantizeTensor calls in MLA function
$content = $content.Replace('DequantizeTensor(kvANorm, kvANormW);', 'DequantizeTensor(kvANorm, kvANormW, liveTypeMap);')
$content = $content.Replace('DequantizeTensor(kvAMqa, kvAMqaW);', 'DequantizeTensor(kvAMqa, kvAMqaW, liveTypeMap);')
$content = $content.Replace('DequantizeTensor(kvB, kvBW);', 'DequantizeTensor(kvB, kvBW, liveTypeMap);')

[IO.File]::WriteAllText('F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp', $content)
Write-Host 'Fixed all issues'
"