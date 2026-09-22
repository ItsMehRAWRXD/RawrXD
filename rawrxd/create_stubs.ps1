# Create all missing stub files needed for CMake configure
$root = "F:\~dev\rawrxd"

# ASM stubs: path -> function_name
$asmStubs = @{
    "src/asm/webview2_masm64_dispatcher.asm" = "webview2_masm64_dispatcher"
    "src/asm/k2_real_attention/RawrXD_K2_RealAttention_x64.asm" = "RawrXD_K2_RealAttention_x64"
    "src/deep2/ResidencyTrace.asm" = "ResidencyTrace"
    "src/benchmark/tree_attention_masm_val038.asm" = "tree_attention_masm_val038"
    "src/masm/rawrxd_math_masm.asm" = "rawrxd_math_masm"
    "src/masm/rawrxd_transformer_masm_fixed.asm" = "rawrxd_transformer_masm_fixed"
    "src/masm/rawrxd_transformer_full.asm" = "rawrxd_transformer_full"
    "src/deep2/sovereign_deep2_kernels.asm" = "sovereign_deep2_kernels"
    "src/deep2/sovereign_q4k_gemv.asm" = "sovereign_q4k_gemv"
    "src/deep2/sovereign_q4k_gemv_v2.asm" = "sovereign_q4k_gemv_v2"
    "src/deep2/sovereign_q2k_gemv_v2.asm" = "sovereign_q2k_gemv_v2"
    "src/deep2/sovereign_q3k_gemv_v2.asm" = "sovereign_q3k_gemv_v2"
    "src/deep2/sovereign_moe_fused.asm" = "sovereign_moe_fused"
    "src/deep2/sovereign_q6_k_gemv.asm" = "sovereign_q6_k_gemv"
    "src/deep2/sovereign_q4_1_gemv.asm" = "sovereign_q4_1_gemv"
    "src/deep2/sovereign_q5_k_gemv.asm" = "sovereign_q5_k_gemv"
    "src/deep2/sovereign_q8_0_gemv.asm" = "sovereign_q8_0_gemv"
    "src/deep2/sovereign_fp16_gemv.asm" = "sovereign_fp16_gemv"
    "src/deep2/sovereign_q4_0_gemv.asm" = "sovereign_q4_0_gemv"
    "src/deep2/sovereign_fp8_gemv.asm" = "sovereign_fp8_gemv"
    "src/deep2/sovereign_iq2_xxs_gemv.asm" = "sovereign_iq2_xxs_gemv"
    "src/deep2/sovereign_iq3_xxs_gemv.asm" = "sovereign_iq3_xxs_gemv"
    "src/deep2/sovereign_iq4_nl_gemv.asm" = "sovereign_iq4_nl_gemv"
    "src/deep2/sovereign_q2_k_gemv.asm" = "sovereign_q2_k_gemv"
    "src/deep2/sovereign_q3_k_gemv.asm" = "sovereign_q3_k_gemv"
    "src/deep2/Sovereign_Attention_KV_AVX512.asm" = "Sovereign_Attention_KV_AVX512"
    "src/deep2/QuantKB.asm" = "QuantKB"
    "src/asm/Deep2Device_Score.asm" = "Deep2Device_Score"
    "src/asm/Deep2Device_Pick.asm" = "Deep2Device_Pick"
    "src/asm/Deep2R1_StrEq.asm" = "Deep2R1_StrEq"
    "src/asm/Deep2R1_IsArch.asm" = "Deep2R1_IsArch"
    "src/asm/Deep2R1_GlobData.asm" = "Deep2R1_GlobData"
    "src/asm/Deep2R1_MlaData.asm" = "Deep2R1_MlaData"
    "src/asm/Deep2R1_MoeData.asm" = "Deep2R1_MoeData"
    "src/asm/Deep2R1_Scan.asm" = "Deep2R1_Scan"
    "src/asm/view_state_x64.asm" = "view_state_x64"
    "src/asm/tensor_masm.asm" = "tensor_masm"
}

foreach ($entry in $asmStubs.GetEnumerator()) {
    $path = Join-Path $root $entry.Key
    $func = $entry.Value
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $content = @"
; Auto-generated stub for $func
.code
PUBLIC ${func}_Stub
${func}_Stub PROC
    xor eax, eax
    ret
${func}_Stub ENDP
END
"@
    [System.IO.File]::WriteAllText($path, $content)
    Write-Output "Created ASM stub: $path"
}

# C++ stubs
$cppStubs = @(
    "validation/fault_injection/FaultInjector.cpp"
    "validation/fault_injection/WorkerCrashInjector.cpp"
    "validation/fault_injection/MemoryPressureInjector.cpp"
    "validation/fault_injection/ServiceKillInjector.cpp"
    "validation/fault_injection/StateCorruptionInjector.cpp"
    "validation/fault_injection/ExceptionStormInjector.cpp"
    "validation/recovery_telemetry/RecoveryTelemetry.cpp"
    "Ship/RawrXD_AutonomousAgenticPipeline.cpp"
    "B012/build/amortization_test.cpp"
    "B013/build/stability_test.cpp"
    "B014/build/compute_decomposition.cpp"
    "B014/build/b014_boundary_probe.cpp"
    "B014/build/b014_single_boundary.cpp"
    "B014/build/b014_lifetime_probe.cpp"
)

foreach ($rel in $cppStubs) {
    $path = Join-Path $root $rel
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($rel)
    $content = "// Auto-generated stub for $base`n"
    [System.IO.File]::WriteAllText($path, $content)
    Write-Output "Created CPP stub: $path"
}

Write-Output "Done"
