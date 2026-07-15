$Script:ErrorActionPreference = 'Stop'
$Script:roots = @('D:\rawrxd\src', 'D:\rawrxd\Ship')
$Script:files = Get-ChildItem -Path $roots -Recurse -Filter *.asm -File
$Script:mnem = @{}
$Script:ext = @{
    call = 0; extern = 0; invoke = 0; includelib = 0; include = 0
    proto = 0; extrn = 0; public = 0; import = 0
}
foreach ($f in $files) {
    Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue | ForEach-Object {
$Script:line = $_
$Script:sc = $line.IndexOf(';')
        if ($sc -ge 0) { $line = $line.Substring(0, $sc) }
$Script:line = $line.Trim()
        if ($line.Length -eq 0) { return }
        if ($line.StartsWith('.')) { return }
$Script:parts = $line -split '\s+', 20, [System.StringSplitOptions]::RemoveEmptyEntries
$Script:i = 0
        while ($i -lt $parts.Count) {
$Script:t = $parts[$i]
            if ($t -match ':$') { $i++; continue }
$Script:tok = $t.ToLowerInvariant()
            foreach ($k in @('call','extern','invoke','includelib','include','proto','extrn','public','import')) {
                if ($tok -eq $k) { $ext[$k] = $ext[$k] + 1 }
            }
            if ($tok -match '^(rep|repe|repz|repne|repnz|lock|xacquire|xrelease)$') { $i++; continue }
            if (-not ($mnem.ContainsKey($tok))) { $mnem[$tok] = 0 }
            $mnem[$tok] = $mnem[$tok] + 1
            break
        }
    }
}
'--- TOP TOKENS (first non-label token per line; includes directives mixed as first token) ---'
$mnem.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 150 | ForEach-Object { "$($_.Value)`t$($_.Key)" }
'--- MASM EXTERNAL-ish KEYWORD HITS (any line where first token matches) ---'
$ext.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)`t$($_.Value)" }
"--- File count: $($files.Count) ---"
