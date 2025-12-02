<#
.SYNOPSIS
    Apply Agentic Theme to RawrXD IDE
.DESCRIPTION
    This script patches RawrXD.ps1 with the proper Agentic IDE theme:
    - Dark background (near black)
    - Purple code text for high visibility
    - Starlight baby blue highlights
    - Proper focus handlers to prevent grey-out issues
.NOTES
    The "Ghost in the Machine" aesthetic for AI-First development
#>

param(
    [switch]$Preview,
    [switch]$Backup
)

$ErrorActionPreference = "Stop"

# Agentic Theme Colors
$Theme = @{
    # Backgrounds
    BackgroundDark = "15, 15, 20"       # Near black with slight blue tint
    BackgroundMid = "25, 25, 35"        # Slightly lighter for panels
    BackgroundInput = "30, 30, 40"      # Input fields
    BackgroundHover = "40, 40, 55"      # Hover states

    # Text Colors
    CodePurple = "200, 150, 255"        # Bright purple for code
    TextWhite = "230, 230, 240"         # Soft white for general text
    TextMuted = "150, 150, 170"         # Muted text

    # Accent Colors (AI Synthesia)
    FlowBlue = "135, 206, 250"          # Starlight baby blue - AI confident
    ConcernOrange = "255, 180, 100"     # AI analyzing
    StuckRed = "255, 150, 150"          # AI needs help
    SuccessGreen = "150, 255, 150"      # Success states

    # Highlights
    SelectionBlue = "60, 80, 120"       # Selection background
    HighlightBlue = "100, 149, 237"     # Code highlights
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         🎨 RawrXD Agentic Theme Patcher                      ║" -ForegroundColor Cyan
Write-Host "║         'Ghost in the Machine' AI-First Aesthetic            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$rawrxdPath = Join-Path $PSScriptRoot "RawrXD.ps1"

if (-not (Test-Path $rawrxdPath)) {
    Write-Host "❌ RawrXD.ps1 not found at: $rawrxdPath" -ForegroundColor Red
    exit 1
}

# Create backup if requested
if ($Backup) {
    $backupPath = Join-Path $PSScriptRoot "RawrXD-PreTheme-$(Get-Date -Format 'yyyyMMdd-HHmmss').ps1"
    Copy-Item $rawrxdPath $backupPath -Force
    Write-Host "✅ Backup created: $backupPath" -ForegroundColor Green
}

Write-Host "`n📖 Reading RawrXD.ps1..." -ForegroundColor Yellow
$content = Get-Content $rawrxdPath -Raw

# Track changes
$changes = @()

# ============================================================================
# FIX 1: Main Code Editor Colors
# ============================================================================
Write-Host "🔧 Fixing main code editor colors..." -ForegroundColor Yellow

$editorOldPattern = @'
# SET INITIAL COLORS - Critical for text visibility
$script:editor.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$script:editor.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
'@

$editorNewCode = @"
# SET INITIAL COLORS - Agentic Theme (Purple Code on Dark)
`$script:editor.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))
`$script:editor.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.CodePurple))
"@

if ($content -match [regex]::Escape($editorOldPattern)) {
    $content = $content -replace [regex]::Escape($editorOldPattern), $editorNewCode
    $changes += "Main editor colors updated to purple on dark"
}

# Fix editor GotFocus handler
$editorFocusOld = @'
$script:editor.Add_GotFocus({
    param($sender, $e)
    $sender.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $sender.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $sender.SelectionColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
})
'@

$editorFocusNew = @"
`$script:editor.Add_GotFocus({
    param(`$sender, `$e)
    `$sender.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))
    `$sender.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.CodePurple))
    `$sender.SelectionColor = [System.Drawing.Color]::FromArgb($($Theme.CodePurple))
})
"@

if ($content -match [regex]::Escape($editorFocusOld)) {
    $content = $content -replace [regex]::Escape($editorFocusOld), $editorFocusNew
    $changes += "Editor GotFocus handler updated"
}

# Fix editor KeyPress handler
$editorKeyOld = @'
$script:editor.Add_KeyPress({
    param($sender, $e)
    $sender.SelectionColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
})
'@

$editorKeyNew = @"
`$script:editor.Add_KeyPress({
    param(`$sender, `$e)
    `$sender.SelectionColor = [System.Drawing.Color]::FromArgb($($Theme.CodePurple))
})
"@

if ($content -match [regex]::Escape($editorKeyOld)) {
    $content = $content -replace [regex]::Escape($editorKeyOld), $editorKeyNew
    $changes += "Editor KeyPress handler updated"
}

# ============================================================================
# FIX 2: Chat Box Colors
# ============================================================================
Write-Host "🔧 Fixing chat box colors..." -ForegroundColor Yellow

$chatBoxOld = @'
    $chatBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $chatBox.ForeColor = [System.Drawing.Color]::White
'@

$chatBoxNew = @"
    `$chatBox.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))
    `$chatBox.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.FlowBlue))
"@

if ($content -match [regex]::Escape($chatBoxOld)) {
    $content = $content -replace [regex]::Escape($chatBoxOld), $chatBoxNew
    $changes += "ChatBox colors updated to starlight blue"
}

# Fix chatBox GotFocus
$chatFocusOld = @'
    $chatBox.Add_GotFocus({
        param($sender, $e)
        $sender.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $sender.ForeColor = [System.Drawing.Color]::White
    })
'@

$chatFocusNew = @"
    `$chatBox.Add_GotFocus({
        param(`$sender, `$e)
        `$sender.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))
        `$sender.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.FlowBlue))
    })
"@

if ($content -match [regex]::Escape($chatFocusOld)) {
    $content = $content -replace [regex]::Escape($chatFocusOld), $chatFocusNew
    $changes += "ChatBox GotFocus handler updated"
}

# ============================================================================
# FIX 3: Input Box Colors
# ============================================================================
Write-Host "🔧 Fixing input box colors..." -ForegroundColor Yellow

$inputBoxOld = @'
    $inputBox.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $inputBox.ForeColor = [System.Drawing.Color]::White
'@

$inputBoxNew = @"
    `$inputBox.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundInput))
    `$inputBox.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.TextWhite))
"@

if ($content -match [regex]::Escape($inputBoxOld)) {
    $content = $content -replace [regex]::Escape($inputBoxOld), $inputBoxNew
    $changes += "InputBox colors updated"
}

# Fix inputBox GotFocus
$inputFocusOld = @'
    $inputBox.Add_GotFocus({
        param($sender, $e)
        $sender.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
        $sender.ForeColor = [System.Drawing.Color]::White
    })
'@

$inputFocusNew = @"
    `$inputBox.Add_GotFocus({
        param(`$sender, `$e)
        `$sender.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundInput))
        `$sender.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.TextWhite))
    })
"@

if ($content -match [regex]::Escape($inputFocusOld)) {
    $content = $content -replace [regex]::Escape($inputFocusOld), $inputFocusNew
    $changes += "InputBox GotFocus handler updated"
}

# Fix inputBox KeyPress
$inputKeyOld = @'
    $inputBox.Add_KeyPress({
        param($sender, $e)
        $sender.ForeColor = [System.Drawing.Color]::White
    })
'@

$inputKeyNew = @"
    `$inputBox.Add_KeyPress({
        param(`$sender, `$e)
        `$sender.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.TextWhite))
    })
"@

if ($content -match [regex]::Escape($inputKeyOld)) {
    $content = $content -replace [regex]::Escape($inputKeyOld), $inputKeyNew
    $changes += "InputBox KeyPress handler updated"
}

# ============================================================================
# FIX 4: Git Status Box Colors
# ============================================================================
Write-Host "🔧 Fixing git status box colors..." -ForegroundColor Yellow

# Generic pattern for other text boxes
$genericOldColors = @(
    @{
        Old = '$gitStatusBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)'
        New = "`$gitStatusBox.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))"
    },
    @{
        Old = '$gitStatusBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)'
        New = "`$gitStatusBox.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.TextWhite))"
    },
    @{
        Old = '$terminalOutput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)'
        New = "`$terminalOutput.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))"
    },
    @{
        Old = '$terminalOutput.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)'
        New = "`$terminalOutput.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.SuccessGreen))"
    },
    @{
        Old = '$agentTaskDetails.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)'
        New = "`$agentTaskDetails.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))"
    },
    @{
        Old = '$agentTaskDetails.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)'
        New = "`$agentTaskDetails.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.FlowBlue))"
    }
)

foreach ($colorFix in $genericOldColors) {
    if ($content -match [regex]::Escape($colorFix.Old)) {
        $content = $content -replace [regex]::Escape($colorFix.Old), $colorFix.New
        $changes += "Updated: $($colorFix.Old.Substring(0, [Math]::Min(50, $colorFix.Old.Length)))..."
    }
}

# ============================================================================
# FIX 5: DevConsole Colors
# ============================================================================
Write-Host "🔧 Fixing dev console colors..." -ForegroundColor Yellow

$devConsoleOld = '$global:devConsole.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)'
$devConsoleNew = "`$global:devConsole.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundDark))"

if ($content -match [regex]::Escape($devConsoleOld)) {
    $content = $content -replace [regex]::Escape($devConsoleOld), $devConsoleNew
    $changes += "DevConsole background updated"
}

$devConsoleForeOld = '$global:devConsole.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)'
$devConsoleForeNew = "`$global:devConsole.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.SuccessGreen))"

if ($content -match [regex]::Escape($devConsoleForeOld)) {
    $content = $content -replace [regex]::Escape($devConsoleForeOld), $devConsoleForeNew
    $changes += "DevConsole foreground updated to green"
}

# ============================================================================
# FIX 6: Search Box Colors
# ============================================================================
Write-Host "🔧 Fixing search box colors..." -ForegroundColor Yellow

$searchBoxOld = @'
    $searchBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $searchBox.ForeColor = [System.Drawing.Color]::White
'@

$searchBoxNew = @"
    `$searchBox.BackColor = [System.Drawing.Color]::FromArgb($($Theme.BackgroundInput))
    `$searchBox.ForeColor = [System.Drawing.Color]::FromArgb($($Theme.TextWhite))
"@

if ($content -match [regex]::Escape($searchBoxOld)) {
    $content = $content -replace [regex]::Escape($searchBoxOld), $searchBoxNew
    $changes += "SearchBox colors updated"
}

# ============================================================================
# Output Results
# ============================================================================

Write-Host "`n📊 Changes Summary:" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

if ($changes.Count -eq 0) {
    Write-Host "⚠️  No patterns matched - file may already be patched or has different formatting" -ForegroundColor Yellow
} else {
    foreach ($change in $changes) {
        Write-Host "  ✅ $change" -ForegroundColor Green
    }
}

if ($Preview) {
    Write-Host "`n🔍 Preview mode - no changes written" -ForegroundColor Yellow
} else {
    Write-Host "`n💾 Writing changes to RawrXD.ps1..." -ForegroundColor Yellow
    Set-Content -Path $rawrxdPath -Value $content -Encoding UTF8
    Write-Host "✅ RawrXD.ps1 updated successfully!" -ForegroundColor Green
}

Write-Host "`n🎨 Agentic Theme Colors Applied:" -ForegroundColor Cyan
Write-Host "  • Code Text: Purple ($($Theme.CodePurple))" -ForegroundColor Magenta
Write-Host "  • Chat/AI: Starlight Blue ($($Theme.FlowBlue))" -ForegroundColor Cyan
Write-Host "  • Terminal: Green ($($Theme.SuccessGreen))" -ForegroundColor Green
Write-Host "  • Background: Near Black ($($Theme.BackgroundDark))" -ForegroundColor DarkGray

Write-Host "`n🚀 Run RawrXD.ps1 to see the new theme!" -ForegroundColor Green
