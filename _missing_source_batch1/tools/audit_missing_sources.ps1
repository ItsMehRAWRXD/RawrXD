param(
  [string]$Repo="F:\~dev\rawrxd",
  [string]$Out="F:\~dev\rawrxd_missing_source_report.csv"
)
$ErrorActionPreference="Stop"
$Repo=(Resolve-Path $Repo).Path
$rows=@()
Get-ChildItem $Repo -Recurse -File -Filter CMakeLists.txt | ForEach-Object {
  $cmake=$_
  $text=Get-Content $cmake.FullName -Raw
  [regex]::Matches($text,'(?im)(?<p>[A-Za-z0-9_./\\+\-]+?\.(?:c|cc|cpp|cxx|asm|s|rc))') |
  ForEach-Object {
    $raw=$_.Groups['p'].Value
    $full=Join-Path $cmake.Directory.FullName ($raw -replace '/','\')
    if (Test-Path -LiteralPath $full) { return }
    $leaf=[IO.Path]::GetFileName($raw)
    $stem=[IO.Path]::GetFileNameWithoutExtension($raw)

    $same=@(Get-ChildItem $Repo -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object Name -IEQ $leaf | Select-Object -Expand FullName)
    $stubs=@(Get-ChildItem $Repo -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.BaseName -match [regex]::Escape($stem) -and $_.Name -match 'stub' } |
      Select-Object -Expand FullName)
    $hits=@(Get-ChildItem $Repo -Recurse -File -Include *.h,*.hpp,*.cpp,*.cxx,*.cc |
      Select-String -SimpleMatch $stem -ErrorAction SilentlyContinue |
      Select-Object -First 12 | ForEach-Object { "$($_.Path):$($_.LineNumber)" })

    $class = if ($same) {"MOVED_OR_DUPLICATED"}
      elseif ($stubs) {"STUB_ONLY_DO_NOT_SHIP"}
      elseif ($hits) {"LIVE_REFERENCE_REVIEW"}
      else {"LIKELY_GHOST_REFERENCE"}

    $rows += [pscustomobject]@{
      CMakeFile=$cmake.FullName; MissingSource=$raw; Classification=$class;
      SameName=($same -join ';'); StubMatches=($stubs -join ';');
      SymbolHits=($hits -join ';')
    }
  }
}
$rows | Sort-Object CMakeFile,MissingSource -Unique |
  Export-Csv $Out -NoTypeInformation -Encoding UTF8
$rows | Group-Object Classification | Format-Table Name,Count -AutoSize
Write-Host "Report: $Out"
