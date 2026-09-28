$content = Get-Content f:\~dev\rawrxd\CMakeLists.txt -Raw
$lines = $content -split "`r?`n"
$targets = @(
    'Omega1Engine','RawrXD-InferenceEngine','rawrxd-monaco-gen',
    'Deep2Engine_IntegrationTest','Deep2Engine_MetadataRegressionTest',
    'RawrXD-InferenceRoutingTest','arch_cert_tensor_inventory',
    'RawrXD-Benchmark','RawrXD-FusedBenchmark','RawrXD-KVBenchmark',
    'Fix4_FlashAttention_Benchmark','Fix5_FusedQuantized_Benchmark',
    'VAL032_SpeculativeDecoding_Benchmark','VAL032_AVX512_Benchmark',
    'tree_attention_bench_simple','tree_attention_profiled',
    'tree_attention_aligned','tree_attention_tiled',
    'tree_attention_vectorized','tree_attention_sparse',
    'tree_attention_fused_sparse','tree_attention_tree_specialized',
    'VAL038_FusedAttention_Benchmark','VAL038_Validation_Benchmark',
    'RawrXD-ModelAnalysis','TestSovereignBridge','TestDebugBridgeTelemetry',
    'stress_target','stress_memory','test_simulator'
)
$changed = 0
foreach ($t in $targets) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match "^\s*add_executable\s*\(\s*$t\b" -or $l -match "^\s*add_library\s*\(\s*$t\b") {
            if ($l -notmatch "^\s*#") { $lines[$i] = "# $l"; $changed++ }
        }
        elseif ($l -match "^\s*target_link_libraries\s*\(\s*$t\b" -or $l -match "^\s*target_include_directories\s*\(\s*$t\b" -or $l -match "^\s*target_compile_options\s*\(\s*$t\b" -or $l -match "^\s*target_compile_features\s*\(\s*$t\b" -or $l -match "^\s*target_compile_definitions\s*\(\s*$t\b" -or $l -match "^\s*target_sources\s*\(\s*$t\b" -or $l -match "^\s*target_link_directories\s*\(\s*$t\b") {
            if ($l -notmatch "^\s*#") { $lines[$i] = "# $l"; $changed++ }
        }
        elseif ($l -match "^\s*set_target_properties\s*\(\s*$t\b" -or $l -match "^\s*set_property\s*\(\s*TARGET\s+$t\b") {
            if ($l -notmatch "^\s*#") { $lines[$i] = "# $l"; $changed++ }
        }
    }
}
# Remove Omega1Engine from any target_link_libraries lists
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^\s*target_link_libraries\s*\(" -and $lines[$i] -notmatch "^\s*#" -and $lines[$i] -match "\bOmega1Engine\b") {
        $lines[$i] = ($lines[$i] -replace "\s*Omega1Engine", "")
        $changed++
    }
}
$out = $lines -join "`n"
Set-Content -Path f:\~dev\rawrxd\CMakeLists.txt -Value $out -NoNewline -Encoding UTF8
Write-Output "Lines commented/modified: $changed"