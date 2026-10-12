$content = [IO.File]::ReadAllText("F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp")

$old = @"
        // Then write all V (vSize = heads * value)
        for (size_t head = 0; head < heads; ++head) {
            const size_t src = head * (noRope + value) + noRope;
            const size_t dst = kSize + head * value;
            std::memcpy(output + dst, expanded.data() + src, value * sizeof(float))
        }
        return true;
"@

$new = @"
            // V
            std::memcpy(output + dst + keyDim, expanded.data() + src + noRope, value * sizeof(float));
        }
        return true;
"@

if ($content.Contains($old)) {
    $content = $content.Replace($old, $new)
    [IO.File]::WriteAllText("F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp", $content)
    Write-Host "Fixed MLA packing"
} else {
    Write-Host "Pattern not found"
}