# Fix all dot-label references in ASM files to use plain labels
# MASM doesn't support .label syntax - needs plain labels

$files = Get-ChildItem -Path 'd:\rawrxd\compilers\sovereign_universal_transpiler' -Recurse -Filter '*.asm'

foreach ($file in $files) {
    $content = Get-Content -Raw $file.FullName
    $original = $content
    
    # Fix label definitions: .label: -> label:
    # Match lines that start with whitespace then .word: 
    $content = $content -replace '(?m)^(\s+)\.(\w+):', '$1$2:'
    
    # Fix jump/call targets: je .label -> je label, jmp .label -> jmp label, etc.
    $content = $content -replace '\b(je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|jo|jno|js|jns|jp|jnp|jc|jnc|jmp|call)\s+\.(\w+)', '$1 $2'
    
    if ($content -ne $original) {
        Set-Content -Path $file.FullName -Value $content -NoNewline
        Write-Host "Fixed: $($file.Name)" -ForegroundColor Green
    }
}

Write-Host "`nDone!" -ForegroundColor Cyan