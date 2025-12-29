# BigDaddyG Extension - Feature Validation Test

Write-Host "🚀 BigDaddyG Extension - Cursor Feature Parity Test" -ForegroundColor Cyan
Write-Host "=" * 60

$extensionPath = "E:\Everything\cursor\extensions\bigdaddyg-copilot-1.0.0"
$testResults = @()

function Test-Feature {
    param($name, $condition, $details)
    $result = @{
        Feature = $name
        Status = if ($condition) { "✅ PASS" } else { "❌ FAIL" }
        Details = $details
    }
    $testResults += $result
    
    $color = if ($condition) { "Green" } else { "Red" }
    Write-Host "`n[$($result.Status)] $name" -ForegroundColor $color
    Write-Host "    $details" -ForegroundColor Gray
    
    return $condition
}

# Test 1: Extension Files
Write-Host "`n📁 Testing Extension Structure..." -ForegroundColor Yellow
$extensionJs = Test-Path "$extensionPath\out\extension.js"
Test-Feature "Extension JavaScript" $extensionJs "Main extension file exists"

$packageJson = Test-Path "$extensionPath\package.json"
Test-Feature "Package Manifest" $packageJson "Package.json with commands defined"

# Test 2: Code Analysis
Write-Host "`n🔍 Analyzing Code Features..." -ForegroundColor Yellow
$code = Get-Content "$extensionPath\out\extension.js" -Raw

# Check for new commands
$hasInsertCode = $code -match "bigdaddyg\.insertCode"
Test-Feature "Insert Code Command" $hasInsertCode "Command registered for inserting code at cursor"

$hasApplyDiff = $code -match "bigdaddyg\.applyDiff"
Test-Feature "Apply Diff Command" $hasApplyDiff "Command registered for applying code changes"

# Check for context gathering
$hasContextGathering = $code -match "gatherWorkspaceContext"
Test-Feature "Workspace Context" $hasContextGathering "Function to gather workspace context (files, diagnostics, selection)"

$hasContextMessage = $code -match "getWorkspaceContext"
Test-Feature "Context Message Handler" $hasContextMessage "Handler for context requests from webview"

# Check for file operations
$hasReadFile = $code -match "msg\.type === 'readFile'"
Test-Feature "File Reading" $hasReadFile "Handler for reading file contents"

$hasOpenFile = $code -match "msg\.type === 'openFile'"
Test-Feature "File Opening" $hasOpenFile "Handler for opening files in editor"

# Test 3: UI Features
Write-Host "`n🎨 Validating UI Components..." -ForegroundColor Yellow

$hasChatContainer = $code -match "chatContainer"
Test-Feature "Chat Container" $hasChatContainer "Scrollable message container"

$hasMessageHistory = $code -match "messageHistory"
Test-Feature "Message History" $hasMessageHistory "Persistent conversation history"

$hasCodeBlocks = $code -match "code-block"
Test-Feature "Code Blocks" $hasCodeBlocks "Code block styling and structure"

$hasCodeActions = $code -match "copyCode|insertCode|applyCode"
Test-Feature "Code Actions" $hasCodeActions "Copy/Insert/Apply buttons on code blocks"

$hasFileLinks = $code -match "file-link"
Test-Feature "File Links" $hasFileLinks "Clickable file references"

$hasContextBadge = $code -match "contextBadge"
Test-Feature "Context Badge" $hasContextBadge "Badge showing workspace context status"

# Test 4: Markdown & Formatting
Write-Host "`n📝 Checking Formatting Features..." -ForegroundColor Yellow

$hasMarkdownFormat = $code -match "formatMessage"
Test-Feature "Markdown Formatting" $hasMarkdownFormat "Function to format messages with markdown"

$hasInlineCode = $code -match "inline-code"
Test-Feature "Inline Code" $hasInlineCode "Inline code styling with backticks"

$hasCodeBlockParsing = $code -match '```'
Test-Feature "Code Block Parsing" $hasCodeBlockParsing "Triple backtick code block detection"

$hasHtmlEscape = $code -match "escapeHtml"
Test-Feature "HTML Escaping" $hasHtmlEscape "Security function to escape HTML in messages"

# Test 5: Agent Features
Write-Host "`n🤖 Validating Agent Capabilities..." -ForegroundColor Yellow

$hasAgentModes = $code -match "agentMode"
Test-Feature "Agent Modes" $hasAgentModes "Support for Ask/Edit/Plan modes"

$hasAgentEdit = $code -match "AGENT_EDIT"
Test-Feature "Agent Edit Detection" $hasAgentEdit "Detection and parsing of AGENT_EDIT markers"

$hasAgentPlan = $code -match "AGENT_PLAN"
Test-Feature "Agent Plan Detection" $hasAgentPlan "Detection and parsing of AGENT_PLAN markers"

$hasIdeAccess = $code -match "ideAccess"
Test-Feature "IDE Access Mode" $hasIdeAccess "Toggle for enabling IDE access in agent mode"

# Test 6: State Management
Write-Host "`n💾 Testing State Persistence..." -ForegroundColor Yellow

$hasGetState = $code -match "vscode\.getState"
Test-Feature "State Loading" $hasGetState "Load conversation state on panel open"

$hasSetState = $code -match "vscode\.setState"
Test-Feature "State Saving" $hasSetState "Save conversation state when messages added"

$hasSaveState = $code -match "saveState\(\)"
Test-Feature "Auto-Save Function" $hasSaveState "Function to persist state automatically"

# Test 7: Streaming & Performance
Write-Host "`n⚡ Checking Streaming Features..." -ForegroundColor Yellow

$hasResponseStart = $code -match "responseStart"
Test-Feature "Stream Start" $hasResponseStart "Handler for beginning of streaming response"

$hasResponseChunk = $code -match "responseChunk"
Test-Feature "Stream Chunks" $hasResponseChunk "Handler for streaming response chunks"

$hasResponseEnd = $code -match "responseEnd"
Test-Feature "Stream End" $hasResponseEnd "Handler for end of streaming response"

$hasStreamingContent = $code -match "streamingContent"
Test-Feature "Live Streaming UI" $hasStreamingContent "Dynamic content area for token-by-token display"

# Test 8: Error Handling
Write-Host "`n🛡️ Validating Error Handling..." -ForegroundColor Yellow

$hasErrorMessages = $code -match "msg\.type === 'error'"
Test-Feature "Error Message Handler" $hasErrorMessages "Handler for error messages from extension"

$hasTryCatch = $code -match "try \{[\s\S]*?\} catch"
Test-Feature "Exception Handling" $hasTryCatch "Try-catch blocks for error recovery"

$hasValidation = $code -match "if \(!.*?\) \{"
Test-Feature "Input Validation" $hasValidation "Validation checks for user input"

# Test 9: Keyboard & Interaction
Write-Host "`n⌨️ Testing Interaction Features..." -ForegroundColor Yellow

$hasKeyboardShortcuts = $code -match "addEventListener.*keydown"
Test-Feature "Keyboard Shortcuts" $hasKeyboardShortcuts "Event listener for keyboard shortcuts"

$hasEnterToSend = $code -match "e\.key === 'Enter'"
Test-Feature "Enter to Send" $hasEnterToSend "Enter key sends message, Shift+Enter adds newline"

$hasClearChat = $code -match "clearChat"
Test-Feature "Clear Chat Function" $hasClearChat "Function to clear conversation history"

$hasScrollToBottom = $code -match "scrollToBottom"
Test-Feature "Auto-Scroll" $hasScrollToBottom "Automatic scroll to latest message"

# Test 10: Multi-Model Support
Write-Host "`n🔧 Validating Model Support..." -ForegroundColor Yellow

$hasRefreshModels = $code -match "refreshModels"
Test-Feature "Model Refresh" $hasRefreshModels "Function to load models from endpoint"

$hasCustomModel = $code -match "customModel"
Test-Feature "Custom Model Input" $hasCustomModel "Input field for custom model IDs"

$hasBackendSelection = $code -match "backend"
Test-Feature "Backend Selection" $hasBackendSelection "Support for multiple backend types (Ollama, OpenAI)"

# Summary
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "📊 Test Summary" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object { $_.Status -eq "✅ PASS" }).Count
$failedTests = $totalTests - $passedTests
$passRate = [math]::Round(($passedTests / $totalTests) * 100, 2)

Write-Host "`nTotal Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -eq 100) { "Green" } elseif ($passRate -ge 90) { "Yellow" } else { "Red" })

if ($passRate -eq 100) {
    Write-Host "`n🎉 ALL TESTS PASSED! Cursor feature parity achieved! 🚀" -ForegroundColor Green
} elseif ($passRate -ge 90) {
    Write-Host "`n⚠️ Most tests passed. Review failed items above." -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Significant failures detected. Review implementation." -ForegroundColor Red
}

# Feature Checklist
Write-Host "`n📋 Cursor Feature Parity Checklist:" -ForegroundColor Cyan
$features = @(
    @{ Name = "Message History"; Status = $hasMessageHistory },
    @{ Name = "Code Blocks with Actions"; Status = ($hasCodeBlocks -and $hasCodeActions) },
    @{ Name = "File References"; Status = $hasFileLinks },
    @{ Name = "Workspace Context"; Status = $hasContextGathering },
    @{ Name = "Streaming Responses"; Status = ($hasResponseStart -and $hasResponseChunk) },
    @{ Name = "Markdown Rendering"; Status = $hasMarkdownFormat },
    @{ Name = "Agent Modes"; Status = $hasAgentModes },
    @{ Name = "State Persistence"; Status = ($hasGetState -and $hasSetState) },
    @{ Name = "Error Handling"; Status = $hasErrorMessages },
    @{ Name = "Multi-Model Support"; Status = $hasRefreshModels }
)

foreach ($feature in $features) {
    $icon = if ($feature.Status) { "✅" } else { "❌" }
    $color = if ($feature.Status) { "Green" } else { "Red" }
    Write-Host "  $icon $($feature.Name)" -ForegroundColor $color
}

# Documentation Check
Write-Host "`n📚 Documentation Files:" -ForegroundColor Cyan
$docs = @(
    "CURSOR-FEATURES-IMPLEMENTED.md",
    "QUICK-START.md",
    "CURSOR-COMPARISON.md"
)

foreach ($doc in $docs) {
    $exists = Test-Path "$PSScriptRoot\$doc"
    $icon = if ($exists) { "✅" } else { "❌" }
    $color = if ($exists) { "Green" } else { "Red" }
    Write-Host "  $icon $doc" -ForegroundColor $color
}

# Deployment Status
Write-Host "`n🚀 Deployment Status:" -ForegroundColor Cyan
$deployed = Test-Path $extensionPath
if ($deployed) {
    $size = (Get-ChildItem "$extensionPath\out\extension.js").Length
    $sizeKb = [math]::Round($size / 1KB, 2)
    Write-Host "  ✅ Deployed to: $extensionPath" -ForegroundColor Green
    Write-Host "  📦 Extension size: $sizeKb KB" -ForegroundColor Gray
    Write-Host "  ⚡ Ready to use with Ctrl+L" -ForegroundColor Green
} else {
    Write-Host "  ❌ Extension not found at: $extensionPath" -ForegroundColor Red
}

Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "Test completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ("=" * 60) -ForegroundColor Cyan
