$Script:ErrorActionPreference = 'Stop'

$Script:root = (Get-Location).Path
$Script:files = Get-ChildItem -Path src -Recurse -File -Include *.cpp,*.cc,*.cxx,*.c,*.h,*.hpp
$Script:pattern = '(?ms)^\s*(?:template\s*<[^{};]+>\s*)?(?<sig>(?:[\w:\<\>\~\*&\s]+?)\s+[\w:~]+\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?)\s*\{\s*return\s*(?<ret>0|false|nullptr|\{\}|"")\s*;\s*\}'
$Script:ctrlStarts = @('if', 'for', 'while', 'switch', 'catch')
$Script:qualOnly = @('static', 'virtual', 'inline', 'constexpr', 'consteval', 'constinit', 'friend', 'explicit')

function Is-LikelyCppFunction([string]$sig) {
    if ([string]::IsNullOrWhiteSpace($sig)) { return $false }
$Script:s = ($sig -replace '\s+', ' ').Trim()
$Script:lower = $s.ToLowerInvariant()
    foreach ($kw in $ctrlStarts) {
        if ($lower.StartsWith("$kw ") -or $lower.StartsWith("$kw(")) { return $false }
    }
    if ($lower.StartsWith('function ')) { return $false }
    if ($s -match '\.\.\.args') { return $false }

$Script:paren = $s.IndexOf('(')
    if ($paren -lt 1) { return $false }
$Script:pre = $s.Substring(0, $paren).Trim()
$Script:tokens = @($pre -split '\s+' | Where-Object { $_ -ne '' })
    if ($tokens.Count -le 1) { return $false }
    if ($tokens.Count -eq 2 -and ($qualOnly -contains $tokens[0].ToLowerInvariant())) { return $false }
    return $true
}

$Script:results = New-Object System.Collections.Generic.List[object]
foreach ($f in $files) {
$Script:text = Get-Content -Raw -LiteralPath $f.FullName
    if ([string]::IsNullOrWhiteSpace($text)) { continue }
$Script:matches = [regex]::Matches($text, $pattern)
    foreach ($m in $matches) {
$Script:sig = ($m.Groups['sig'].Value -replace '\s+', ' ').Trim()
        if (-not (Is-LikelyCppFunction $sig)) { continue }
$Script:line = ([regex]::Matches($text.Substring(0, $m.Index), "`n")).Count + 1
$Script:rel = Resolve-Path -LiteralPath $f.FullName -Relative
        if ($rel.StartsWith('.\')) { $rel = $rel.Substring(2) }
        $results.Add([pscustomobject]@{
                File      = $rel
                Line      = $line
                Return    = $m.Groups['ret'].Value
                Signature = $sig
            })
    }
}

$Script:grouped = $results | Sort-Object File, Line | Group-Object File
$Script:outPath = Join-Path $root 'IDE_BARE_RETURN_FUNCTIONS_AUDIT.md'
$Script:sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# Bare Return Function Audit')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('- Scope: `src/**/*.cpp|cc|cxx|c|h|hpp`')
[void]$sb.AppendLine('- Criteria: function bodies with only one statement: `return 0;`, `return false;`, `return nullptr;`, `return {};`, or `return "" ;`')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("- Total matches: $($results.Count)")
[void]$sb.AppendLine("- Files matched: $($grouped.Count)")
[void]$sb.AppendLine('')
foreach ($g in $grouped) {
    [void]$sb.AppendLine("## $($g.Name)")
    foreach ($r in ($g.Group | Sort-Object Line)) {
$Script:sigEsc = $r.Signature.Replace('`', '``')
        [void]$sb.AppendLine(('- L{0}: `{1}` -> `return {2};`' -f $r.Line, $sigEsc, $r.Return))
    }
    [void]$sb.AppendLine('')
}
Set-Content -LiteralPath $outPath -Value $sb.ToString() -Encoding UTF8

Write-Output "WROTE=$outPath"
Write-Output "TOTAL_MATCHES=$($results.Count)"
Write-Output "FILES_MATCHED=$($grouped.Count)"
