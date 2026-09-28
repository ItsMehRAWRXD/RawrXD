$headers = @('string','vector','map','set','iostream','math','future','random','chrono','mutex','thread','algorithm','numeric','cstring','stdexcept','optional','memory','functional','cstdint','cstddef','cmath','cstdlib','cstring','cassert','limits','fstream','sstream','unordered_map','span','list','deque','queue','stack','bitset','regex','variant','tuple','type_traits','utility','iterator','random','chrono','atomic','thread','mutex','condition_variable','future','algorithm','numeric','cstring','string_view','charconv','numbers','filesystem','compare','concepts','ranges')
$files = Get-ChildItem -Path 'F:\~dev\rawrxd\src' -Recurse -Include *.cpp,*.hpp,*.h
foreach ($file in $files) {
    $content = Get-Content $file -Raw
    $changed = $false
    foreach ($h in $headers) {
        $pattern = "// stub: " + [regex]::Escape($h)
        if ($content -match $pattern) {
            $content = $content -replace $pattern, "#include <$h>"
            $changed = $true
        }
    }
    if ($changed) {
        Set-Content -Path $file.FullName -Value $content -NoNewline
    }
}
Write-Host "Done restoring stubs."
