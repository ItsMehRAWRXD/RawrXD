param([string]$OutDir = "F:\models\gguf")
$ErrorActionPreference = 'Stop'

$rows = @()
foreach ($f in Get-ChildItem $OutDir -File -Filter *.gguf) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
    # names are <ns>__<name>__<tag>[.<layer>]
    $first = $base.IndexOf('__')
    $ns = $base.Substring(0, $first)
    $rest = $base.Substring($first + 2)
    $last = $rest.LastIndexOf('__')
    if ($last -ge 0) {
        $name = $rest.Substring(0, $last)
        $tag  = $rest.Substring($last + 2)
    } else {
        $name = $rest
        $tag  = 'latest'
    }
    $tag = ($tag -replace '\.\d+$','')

    $li = (Get-Item $f.FullName).LinkType

    $rows += [pscustomobject]@{
        model  = ("{0}/{1}" -f $ns, $name) -replace '^library/',''
        ns     = $ns
        name   = $name
        tag    = $tag
        file   = $f.Name
        bytes  = [int64]$f.Length
        gib    = [math]::Round($f.Length/1GB, 2)
        link   = $li
        path   = $f.FullName
    }
}

$manifest = [pscustomobject]@{
    generated  = (Get-Date -Format o)
    out_dir    = $OutDir
    source     = 'Ollama blob store, F:\OllamaModels\blobs'
    count      = $rows.Count
    total_gib  = [math]::Round((($rows | Measure-Object -Property bytes -Sum).Sum)/1GB, 2)
    extra_disk = 0
    note       = 'Every file is a hardlink to an Ollama blob, so the whole set costs no additional disk space.'
    files      = $rows | Sort-Object model, tag, file
}
[System.IO.File]::WriteAllText((Join-Path $OutDir 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4))
Write-Output "wrote manifest.json  count=$($manifest.count) total_gib=$($manifest.total_gib)"
Write-Output ""
$rows | Sort-Object gib -Descending | Select-Object -First 12 | ForEach-Object { "  {0,-40} {1,-18} {2,8} GiB" -f $_.model, $_.tag, $_.gib }
