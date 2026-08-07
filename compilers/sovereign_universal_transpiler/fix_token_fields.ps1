# Fix TOKEN struct field references and remaining dot labels
# MASM reserved words: type, length, flags, value, start, line, column, pad

$files = @(
    'd:\rawrxd\compilers\sovereign_universal_transpiler\kernel\token.asm',
    'd:\rawrxd\compilers\sovereign_universal_transpiler\kernel\lexer.asm',
    'd:\rawrxd\compilers\sovereign_universal_transpiler\kernel\compiler.asm'
)

foreach ($file in $files) {
    if (-not (Test-Path $file)) { continue }
    $content = Get-Content -Raw $file
    $original = $content
    
    # Fix TOKEN struct field references: .TOKEN.type -> .TOKEN.tok_type, etc.
    $content = $content -replace '\.TOKEN\.type\b', '.TOKEN.tok_type'
    $content = $content -replace '\.TOKEN\.flags\b', '.TOKEN.tok_flags'
    $content = $content -replace '\.TOKEN\.start\b', '.TOKEN.tok_start'
    $content = $content -replace '\.TOKEN\.length\b', '.TOKEN.tok_length'
    $content = $content -replace '\.TOKEN\.line\b', '.TOKEN.tok_line'
    $content = $content -replace '\.TOKEN\.column\b', '.TOKEN.tok_column'
    $content = $content -replace '\.TOKEN\.value\b', '.TOKEN.tok_value'
    $content = $content -replace '\.TOKEN\.pad\b', '.TOKEN.tok_pad'
    
    # Fix current_token field references
    $content = $content -replace 'current_token\.type\b', 'current_token.tok_type'
    $content = $content -replace 'current_token\.start\b', 'current_token.tok_start'
    $content = $content -replace 'current_token\.length\b', 'current_token.tok_length'
    $content = $content -replace 'current_token\.line\b', 'current_token.tok_line'
    $content = $content -replace 'current_token\.column\b', 'current_token.tok_column'
    
    # Fix any remaining dot-label definitions: .word: -> word:
    $content = $content -replace '(?m)^(\s+)\.(\w+):', '$1$2:'
    
    # Fix remaining dot-label jump targets
    $content = $content -replace '\b(je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|jo|jno|js|jns|jp|jnp|jc|jnc|jmp|call)\s+\.(\w+)', '$1 $2'
    
    if ($content -ne $original) {
        Set-Content -Path $file -Value $content -NoNewline
        Write-Host "Fixed: $(Split-Path $file -Leaf)" -ForegroundColor Green
    }
}

Write-Host "`nDone!" -ForegroundColor Cyan