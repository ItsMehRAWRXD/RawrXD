param(
    [string]$CMakeFile = "F:\~dev\rawrxd\CMakeLists.txt",
    [string]$BackupFile = "F:\~dev\rawrxd\CMakeLists.txt.bak_source_authority"
)

Copy-Item $CMakeFile $BackupFile -Force
$content = Get-Content $CMakeFile -Raw

# Pattern: capture each ASM block that has set(SRC) + set(OBJ) + add_custom_command
# We need to find blocks starting with "set(ASM_XXX_SRC" and ending at the closing ")" of add_custom_command

$blocks = @()
$regex = [regex]'(?m)(\s*set\(ASM_([A-Z0-9_]+)_SRC\s+"\$\{CMAKE_CURRENT_SOURCE_DIR\}/[^"]+\.asm"\).*?add_custom_command\(\s*OUTPUT\s+\$\{ASM_\2_OBJ\}.*?VERBATIM\s*\)\s*)'

$matches = $regex.Matches($content)
Write-Host "Found $($matches.Count) ASM add_custom_command blocks"

foreach ($m in $matches) {
    $fullBlock = $m.Value
    $varName = $m.Groups[2].Value
    # Check if this block already has an if(EXISTS) wrapper (skip if so)
    if ($fullBlock -match 'if\s*\(\s*EXISTS') { continue }
    
    # Wrap with if(EXISTS)
    $wrapped = @"
if(EXISTS "`${ASM_${varName}_SRC}")
    $fullBlock`nelse()
    set(ASM_${varName}_OBJ "")
    message(STATUS "[RAWRXD_SOURCE_AUTHORITY_001] OMIT absent optional MASM source: `${ASM_${varName}_SRC}")
endif()
"@
    $content = $content.Replace($fullBlock, $wrapped + "`n")
}

Set-Content $CMakeFile $content -NoNewline
Write-Host "Patched $($matches.Count) ASM blocks with if(EXISTS) guards"
