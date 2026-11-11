# Fix compiler stubs - Replace placeholder text with proper language names
$compilerMappings = @{
    'ada_compiler_from_scratch' = 'Ada'
    'assembly_compiler_from_scratch' = 'Assembly'
    'bash_compiler_from_scratch' = 'Bash'
    'c_compiler_from_scratch' = 'C'
    'c__compiler_from_scratch' = 'C++'
    'c___compiler_from_scratch' = 'C#'
    'cadence_compiler_from_scratch' = 'Cadence'
    'carbon_compiler_from_scratch' = 'Carbon'
    'clojure_compiler_from_scratch' = 'Clojure'
    'cobol_compiler_from_scratch' = 'COBOL'
    'cross_compiler' = 'Cross'
    'crystal_compiler_from_scratch' = 'Crystal'
    'dart_compiler_from_scratch' = 'Dart'
    'delphi_compiler_from_scratch' = 'Delphi'
    'elixir_compiler_from_scratch' = 'Elixir'
    'erlang_compiler_from_scratch' = 'Erlang'
    'eon_bootstrap_compiler' = 'EON'
    'eon_compiler_complete' = 'EON'
    'eon_compiler_from_scratch' = 'EON'
    'eon_compiler_main' = 'EON'
    'eon_kernel_compiler' = 'EON'
    'fabric_compiler' = 'Fabric'
    'fortran_compiler_from_scratch' = 'Fortran'
    'f__compiler_from_scratch' = 'F#'
    'full_eon_compiler' = 'Full'
    'go_compiler_from_scratch' = 'Go'
    'haskell_compiler_from_scratch' = 'Haskell'
    'integrated_eon_compiler' = 'Integrated'
    'jai_compiler_from_scratch' = 'Jai'
    'java_compiler_from_scratch' = 'Java'
    'javascript_compiler_from_scratch' = 'JavaScript'
    'julia_compiler_from_scratch' = 'Julia'
    'kotlin_compiler_from_scratch' = 'Kotlin'
    'llvm_ir_compiler_from_scratch' = 'LLVM IR'
    'lua_compiler_from_scratch' = 'Lua'
    'matlab_compiler_from_scratch' = 'MATLAB'
    'motoko_compiler_from_scratch' = 'Motoko'
    'move_compiler_from_scratch' = 'Move'
    'multi_target_compiler' = 'Multi-Target'
    'n0mn0m_cross_platform_compiler' = 'N0MN0M'
    'n0mn0m_quantum_asm_compiler' = 'N0MN0M'
    'nim_compiler_from_scratch' = 'Nim'
    'ocaml_compiler_from_scratch' = 'OCaml'
    'odin_compiler_from_scratch' = 'Odin'
    'pascal_compiler_from_scratch' = 'Pascal'
    'perl_compiler_from_scratch' = 'Perl'
    'php_compiler_from_scratch' = 'PHP'
    'powershell_compiler_from_scratch' = 'PowerShell'
    'python_compiler_from_scratch' = 'Python'
    'r_compiler_from_scratch' = 'R'
    'ruby_compiler_from_scratch' = 'Ruby'
    'rust_compiler_from_scratch' = 'Rust'
    'scala_compiler_from_scratch' = 'Scala'
    'self_contained_compiler_gui' = 'Self-Contained'
    'self_hosted_eon_compiler' = 'Self-Hosted'
    'solidity_compiler_from_scratch' = 'Solidity'
    'swift_compiler_from_scratch' = 'Swift'
    'test_complete_compiler' = 'Test'
    'test_full_eon_compiler' = 'Test'
    'test_self_hosted_compiler' = 'Test'
    'typescript_compiler_from_scratch' = 'TypeScript'
    'uber_elegant_compiler' = 'Uber'
    'universal_compiler_runtime' = 'Universal'
    'universal_compiler_runtime_clean' = 'Universal'
    'universal_cross_platform_compiler' = 'Universal'
    'universal_multi_language_compiler' = 'Universal'
    'vb_net_compiler_from_scratch' = 'VB.NET'
    'v_compiler_from_scratch' = 'V'
    'vyper_compiler_from_scratch' = 'Vyper'
    'webassembly_compiler_from_scratch' = 'WebAssembly'
    'zig_compiler_from_scratch' = 'Zig'
}

$fixedCount = 0
$baseDir = "D:\rawrxd\compilers\all_69"

Get-ChildItem -Path $baseDir -Filter "*.asm" | ForEach-Object {
    $fileName = $_.BaseName
    $fullPath = $_.FullName
    
    # Find matching language name
    $languageName = $null
    foreach ($pattern in $compilerMappings.Keys) {
        if ($fileName -like "*$pattern*") {
            $languageName = $compilerMappings[$pattern]
            break
        }
    }
    
    if ($languageName) {
        $content = Get-Content $fullPath -Raw
        
        # Check if file has placeholder text
        if ($content -match 'Compiler.*1\.0') {
            # Replace the malformed pattern: Compiler" "1.0"" 
            $content = $content -replace '"Compiler" "1\.0""', "`"$languageName Compiler v1.0`""
            
            # Replace other variations
            $content = $content -replace 'Compiler" "1\.0""', "`"$languageName Compiler v1.0`""
            $content = $content -replace '"Compiler" "1\.0"', "`"$languageName Compiler v1.0`""
            
            # Replace in ready message
            $content = $content -replace '"Compiler" "1\.0"" initialized', "`"$languageName Compiler v1.0 initialized`""
            $content = $content -replace '"Compiler" "1\.0"" operational', "`"$languageName Compiler v1.0 operational`""
            
            Set-Content $fullPath $content -NoNewline
            Write-Host "Fixed: $fileName -> $languageName"
            $fixedCount++
        }
    }
}

Write-Host "`nFixed $fixedCount compiler stub files"
