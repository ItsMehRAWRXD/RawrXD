$stubs = @(
    'src/asm/Deep2R1_Decode.asm',
    'src/asm/Deep2R1_Validate.asm',
    'src/asm/Deep2R1_LayerKind.asm',
    'src/asm/Deep2R1_SplitKVB.asm',
    'src/asm/Deep2ThreadAffinity.asm',
    'src/asm/Deep2OuterStr.asm',
    'src/asm/Deep2OuterEnv.asm',
    'src/asm/Deep2OuterParse.asm',
    'src/asm/Deep2OuterParseIdx.asm',
    'src/asm/Deep2OuterGGUF.asm',
    'src/asm/Deep2OuterPath.asm',
    'src/asm/Deep2OuterShardApply.asm',
    'src/asm/Deep2OuterShardScan.asm',
    'src/asm/Deep2OuterShardCheck.asm',
    'src/asm/Deep2OuterPrintIO.asm',
    'src/asm/Deep2OuterPrint.asm',
    'src/asm/Deep2OuterEvidence.asm',
    'src/asm/Deep2OuterResolve.asm',
    'src/asm/Deep2OuterCallEngine.asm',
    'src/asm/Deep2OuterHost.asm',
    'src/asm/RuntimeEvidence512_Core.asm',
    'src/asm/RuntimeEvidence512_Emit.asm',
    'src/asm/RuntimeEvidence512_Collect.asm',
    'src/asm/RuntimeEvidence512_IDEEmit.asm',
    'src/asm/RuntimeEvidence512_IDECollect.asm',
    'src/asm/Deep2R1_Smoke.asm',
    'src/asm/Deep2OuterSmoke.asm'
)

foreach ($rel in $stubs) {
    $path = Join-Path 'F:\~dev\rawrxd' $rel
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($rel)
    $content = "; Auto-generated stub for $base`n.code`nPUBLIC ${base}_Stub`n${base}_Stub PROC`n    xor eax, eax`n    ret`n${base}_Stub ENDP`nEND`n"
    [System.IO.File]::WriteAllText($path, $content)
    Write-Output "Created $path"
}
