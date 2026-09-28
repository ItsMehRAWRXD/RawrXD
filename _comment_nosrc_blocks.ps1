# Comment out all "No SOURCES given to target" blocks in CMakeLists.txt
# For each target, find add_executable(<target> and comment out the contiguous block
# until a blank line, a new comment separator, or another add_executable/add_library.

$cmakeFile = "F:\~dev\rawrxd\CMakeLists.txt"
$lines = Get-Content $cmakeFile -Encoding UTF8

$targets = @(
    'RawrXD-InferenceEngine',
    'RawrXD-InferenceRoutingTest',
    'arch_cert_tensor_inventory',
    'Fix4_FlashAttention_Benchmark',
    'Fix5_FusedQuantized_Benchmark',
    'VAL032_SpeculativeDecoding_Benchmark',
    'VAL032_AVX512_Benchmark',
    'tree_attention_profiled',
    'tree_attention_aligned',
    'tree_attention_tiled',
    'tree_attention_vectorized',
    'tree_attention_sparse',
    'tree_attention_fused_sparse',
    'tree_attention_tree_specialized',
    'VAL038_FusedAttention_Benchmark',
    'VAL038_Validation_Benchmark',
    'TestDebugBridgeTelemetry',
    'stress_target',
    'stress_memory'
)

$modified = [System.Collections.Generic.List[string]]::new()
$i = 0
$commentedRanges = @()

while ($i -lt $lines.Count) {
    $line = $lines[$i]
    $matched = $false

    foreach ($tgt in $targets) {
        # Match add_executable(<target> possibly with whitespace
        if ($line -match "^\s*add_executable\(\s*$([regex]::Escape($tgt))\b") {
            $startIdx = $i
            $j = $i
            # Comment out from here until blank line or a new comment separator or another add_executable/add_library
            while ($j -lt $lines.Count) {
                $cur = $lines[$j]
                if ($j -gt $startIdx) {
                    # Stop at blank line
                    if ($cur.Trim() -eq "") { break }
                    # Stop at a comment line that is NOT "# AUTO-REMOVED"
                    if ($cur.TrimStart().StartsWith("#") -and $cur -notmatch "AUTO-REMOVED") { break }
                    # Stop at another add_executable or add_library (not our target)
                    if ($cur -match "^\s*add_executable\(" -and $cur -notmatch $([regex]::Escape($tgt))) { break }
                    if ($cur -match "^\s*add_library\(") { break }
                }
                $j++
            }
            $endIdx = $j - 1  # last line to comment (inclusive)

            # Comment out lines startIdx..endIdx
            for ($k = $startIdx; $k -le $endIdx; $k++) {
                $modified.Add("# " + $lines[$k])
            }
            $commentedRanges += "$tgt : lines $($startIdx+1)-$($endIdx+1) ($($endIdx - $startIdx + 1) lines)"
            $i = $endIdx + 1
            $matched = $true
            break
        }
    }

    if (-not $matched) {
        $modified.Add($line)
        $i++
    }
}

# Write back
$modified | Set-Content $cmakeFile -Encoding UTF8

"=== Commented out $($commentedRanges.Count) blocks ==="
$commentedRanges | ForEach-Object { "  $_" }