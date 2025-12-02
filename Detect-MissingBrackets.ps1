<#
.SYNOPSIS
    Detects missing brackets, braces, and parentheses in PowerShell scripts
.DESCRIPTION
    Analyzes PowerShell files for unmatched brackets [], braces {}, and parentheses ()
    Reports line numbers and context for each mismatch
.PARAMETER FilePath
    Path to the PowerShell script to analyze
.PARAMETER ShowContext
    Number of lines of context to show around errors (default: 3)
.EXAMPLE
    .\Detect-MissingBrackets.ps1 -FilePath "RawrXD.ps1"
.EXAMPLE
    .\Detect-MissingBrackets.ps1 -FilePath "RawrXD.ps1" -ShowContext 5
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "RawrXD.ps1",

    [Parameter(Mandatory = $false)]
    [int]$ShowContext = 3
)

function Test-BracketBalance {
    param(
        [string]$ScriptPath,
        [int]$ContextLines = 3
    )

    if (-not (Test-Path $ScriptPath)) {
        Write-Host "ERROR: File not found: $ScriptPath" -ForegroundColor Red
        return
    }

    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  PowerShell Bracket/Brace/Parenthesis Balance Checker       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    Write-Host "Analyzing: $ScriptPath" -ForegroundColor Yellow

    # Read file content
    $lines = Get-Content -Path $ScriptPath
    $totalLines = $lines.Count
    Write-Host "Total lines: $totalLines`n" -ForegroundColor Gray

    # Stacks to track opening symbols with line numbers
    $braceStack = New-Object System.Collections.Generic.Stack[object]      # { }
    $bracketStack = New-Object System.Collections.Generic.Stack[object]    # [ ]
    $parenStack = New-Object System.Collections.Generic.Stack[object]      # ( )

    # Track errors
    $errors = @()
    $inMultilineComment = $false
    $inHereString = $false
    $hereStringDelimiter = $null

    # Process each line
    for ($lineNum = 0; $lineNum -lt $lines.Count; $lineNum++) {
        $line = $lines[$lineNum]
        $displayLineNum = $lineNum + 1

        # Track here-strings (multi-line strings)
        if ($line -match '^@["'']$') {
            $inHereString = $true
            $hereStringDelimiter = $line
            continue
        }
        if ($inHereString -and $line -match '^["'']@$') {
            $inHereString = $false
            $hereStringDelimiter = $null
            continue
        }
        if ($inHereString) {
            continue
        }

        # Track multi-line comments
        if ($line -match '<#') {
            $inMultilineComment = $true
        }
        if ($inMultilineComment) {
            if ($line -match '#>') {
                $inMultilineComment = $false
            }
            continue
        }

        # Remove single-line comments and strings for accurate parsing
        $cleanLine = $line -replace '#.*$', ''  # Remove comments
        $cleanLine = $cleanLine -replace '"[^"]*"', '""'  # Remove double-quoted strings
        $cleanLine = $cleanLine -replace "'[^']*'", "''"  # Remove single-quoted strings

        # Process each character
        for ($i = 0; $i -lt $cleanLine.Length; $i++) {
            $char = $cleanLine[$i]

            switch ($char) {
                '{' {
                    $braceStack.Push(@{Line = $displayLineNum; Char = $char; Column = $i + 1 })
                }
                '}' {
                    if ($braceStack.Count -eq 0) {
                        $errors += @{
                            Type   = "Unmatched closing brace"
                            Symbol = '}'
                            Line   = $displayLineNum
                            Column = $i + 1
                            Text   = $line.Trim()
                        }
                    }
                    else {
                        $braceStack.Pop() | Out-Null
                    }
                }
                '[' {
                    $bracketStack.Push(@{Line = $displayLineNum; Char = $char; Column = $i + 1 })
                }
                ']' {
                    if ($bracketStack.Count -eq 0) {
                        $errors += @{
                            Type   = "Unmatched closing bracket"
                            Symbol = ']'
                            Line   = $displayLineNum
                            Column = $i + 1
                            Text   = $line.Trim()
                        }
                    }
                    else {
                        $bracketStack.Pop() | Out-Null
                    }
                }
                '(' {
                    $parenStack.Push(@{Line = $displayLineNum; Char = $char; Column = $i + 1 })
                }
                ')' {
                    if ($parenStack.Count -eq 0) {
                        $errors += @{
                            Type   = "Unmatched closing parenthesis"
                            Symbol = ')'
                            Line   = $displayLineNum
                            Column = $i + 1
                            Text   = $line.Trim()
                        }
                    }
                    else {
                        $parenStack.Pop() | Out-Null
                    }
                }
            }
        }
    }

    # Check for unclosed symbols
    while ($braceStack.Count -gt 0) {
        $item = $braceStack.Pop()
        $errors += @{
            Type   = "Unclosed brace"
            Symbol = '{'
            Line   = $item.Line
            Column = $item.Column
            Text   = $lines[$item.Line - 1].Trim()
        }
    }

    while ($bracketStack.Count -gt 0) {
        $item = $bracketStack.Pop()
        $errors += @{
            Type   = "Unclosed bracket"
            Symbol = '['
            Line   = $item.Line
            Column = $item.Column
            Text   = $lines[$item.Line - 1].Trim()
        }
    }

    while ($parenStack.Count -gt 0) {
        $item = $parenStack.Pop()
        $errors += @{
            Type   = "Unclosed parenthesis"
            Symbol = '('
            Line   = $item.Line
            Column = $item.Column
            Text   = $lines[$item.Line - 1].Trim()
        }
    }

    # Display results
    Write-Host "`n═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    if ($errors.Count -eq 0) {
        Write-Host "✅ SUCCESS: All brackets, braces, and parentheses are balanced!" -ForegroundColor Green
        Write-Host "`nNo errors found.`n" -ForegroundColor Green
    }
    else {
        Write-Host "❌ ERRORS FOUND: $($errors.Count) bracket/brace/parenthesis mismatch(es)`n" -ForegroundColor Red

        # Sort errors by line number
        $errors = $errors | Sort-Object -Property Line

        foreach ($error in $errors) {
            Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
            Write-Host "Error Type: " -NoNewline -ForegroundColor Yellow
            Write-Host $error.Type -ForegroundColor Red
            Write-Host "Symbol: " -NoNewline -ForegroundColor Yellow
            Write-Host $error.Symbol -ForegroundColor Red
            Write-Host "Line: " -NoNewline -ForegroundColor Yellow
            Write-Host "$($error.Line), Column: $($error.Column)" -ForegroundColor Cyan
            Write-Host "`nContext:" -ForegroundColor Yellow

            # Show context lines
            $startLine = [Math]::Max(0, $error.Line - 1 - $ContextLines)
            $endLine = [Math]::Min($lines.Count - 1, $error.Line - 1 + $ContextLines)

            for ($i = $startLine; $i -le $endLine; $i++) {
                $prefix = "  "
                $color = "Gray"

                if ($i -eq ($error.Line - 1)) {
                    $prefix = "→ "
                    $color = "White"
                    Write-Host "$prefix$($i + 1): " -NoNewline -ForegroundColor Red
                    Write-Host $lines[$i] -ForegroundColor $color

                    # Show column pointer
                    $pointer = " " * ($error.Column + $prefix.Length + "$($i + 1): ".Length - 1) + "^"
                    Write-Host $pointer -ForegroundColor Red
                }
                else {
                    Write-Host "$prefix$($i + 1): " -NoNewline -ForegroundColor DarkGray
                    Write-Host $lines[$i] -ForegroundColor $color
                }
            }
            Write-Host ""
        }

        Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

        # Summary
        Write-Host "SUMMARY:" -ForegroundColor Yellow
        Write-Host "  Total Errors: $($errors.Count)" -ForegroundColor Red
        Write-Host "  Unclosed braces: $(($errors | Where-Object { $_.Type -eq 'Unclosed brace' }).Count)" -ForegroundColor Red
        Write-Host "  Unmatched closing braces: $(($errors | Where-Object { $_.Type -eq 'Unmatched closing brace' }).Count)" -ForegroundColor Red
        Write-Host "  Unclosed brackets: $(($errors | Where-Object { $_.Type -eq 'Unclosed bracket' }).Count)" -ForegroundColor Red
        Write-Host "  Unmatched closing brackets: $(($errors | Where-Object { $_.Type -eq 'Unmatched closing bracket' }).Count)" -ForegroundColor Red
        Write-Host "  Unclosed parentheses: $(($errors | Where-Object { $_.Type -eq 'Unclosed parenthesis' }).Count)" -ForegroundColor Red
        Write-Host "  Unmatched closing parentheses: $(($errors | Where-Object { $_.Type -eq 'Unmatched closing parenthesis' }).Count)" -ForegroundColor Red
        Write-Host ""
    }

    return $errors
}

# Run the check
$result = Test-BracketBalance -ScriptPath $FilePath -ContextLines $ShowContext

# Exit with error code if issues found
if ($result.Count -gt 0) {
    exit 1
}
else {
    exit 0
}
