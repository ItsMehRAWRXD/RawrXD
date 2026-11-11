$content = [IO.File]::ReadAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp")

$newFunc = [IO.File]::ReadAllText("F:\rawrxd\mla_new_impl.cpp")

$startIdx = $content.IndexOf("static std::vector<float> ExecuteMLADecompressForward")
if ($startIdx -ge 0) {
    $braceCount = 0
    $inFunction = $false
    $endIdx = -1
    for ($i = $startIdx; $i -lt $content.Length; $i++) {
        $c = $content[$i]
        if ($c -eq '{') { $braceCount++; $inFunction = $true }
        elseif ($c -eq '}') { 
            $braceCount-- 
            if ($inFunction -and $braceCount -eq 0) { $endIdx = $i; break }
        }
    }
    if ($endIdx -ge 0) {
        $content = $content.Substring(0, $startIdx) + $newFunc + $content.Substring($endIdx + 1)
        [IO.File]::WriteAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp", $content)
        Write-Host "Replaced ExecuteMLADecompressForward function"
    } else {
        Write-Host "Function end not found"
    }
} else {
    Write-Host "Function not found"
}