<#
.SYNOPSIS
    RawrXD WebView2 Edition - HTML IDE with PowerShell Backend

.DESCRIPTION
    A hybrid approach combining:
    - Modern HTML/CSS/JavaScript UI (like Electron)
    - Native Windows WebView2 engine (no Chromium overhead)
    - PowerShell backend for system integration
    - Optimized for 4K displays (3840x2160 @ 160Hz)

.EXAMPLE
    .\RawrXD-WebView.ps1
    Launch the WebView2 IDE
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Width = 3200,  # Optimized for 4K display

    [Parameter(Mandatory = $false)]
    [int]$Height = 1800,

    [Parameter(Mandatory = $false)]
    [string]$HtmlPath = "D:\HTML-Projects\IDEre2.html",

    [Parameter(Mandatory = $false)]
    [switch]$FullScreen,

    [Parameter(Mandatory = $false)]
    [switch]$Debug
)

# Global application state
$global:RawrXDWebView = @{
    Version = "3.0.0-WebView2"
    Build = "HTML-PowerShell-Hybrid"
    StartTime = Get-Date
    Form = $null
    WebView = $null
    IsInitialized = $false
    Debug = $Debug.IsPresent
}

# Import required assemblies
function Import-WebView2Assemblies {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Add-Type -AssemblyName Microsoft.VisualBasic

        # Try to load WebView2
        $webView2Path = "$env:LOCALAPPDATA\Microsoft\WindowsApps\Microsoft.WebView2*"
        $webView2Dirs = Get-ChildItem $webView2Path -Directory -ErrorAction SilentlyContinue

        if ($webView2Dirs) {
            $webView2Runtime = $webView2Dirs | Sort-Object Name -Descending | Select-Object -First 1
            Write-Host "✅ WebView2 runtime found: $($webView2Runtime.Name)" -ForegroundColor Green
        }

        # Load WebView2 NuGet package if available
        $nugetPath = "$env:USERPROFILE\.nuget\packages\microsoft.web.webview2"
        if (Test-Path $nugetPath) {
            $latestVersion = Get-ChildItem $nugetPath | Sort-Object Name -Descending | Select-Object -First 1
            $webView2Dll = Join-Path $latestVersion.FullName "lib\net45\Microsoft.Web.WebView2.WinForms.dll"

            if (Test-Path $webView2Dll) {
                Add-Type -Path $webView2Dll
                Write-Host "✅ WebView2 .NET package loaded" -ForegroundColor Green
                return $true
            }
        }

        Write-Host "⚠️  WebView2 .NET package not found, using fallback browser control" -ForegroundColor Yellow
        return $false
    }
    catch {
        Write-Host "⚠️  WebView2 not available: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# Create 4K-optimized form
function New-OptimizedForm {
    param(
        [int]$Width,
        [int]$Height,
        [bool]$FullScreen
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD WebView2 - HTML IDE with PowerShell Backend"
    $form.StartPosition = "CenterScreen"

    if ($FullScreen) {
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    }
    else {
        $form.Size = New-Object System.Drawing.Size($Width, $Height)
        $form.MinimumSize = New-Object System.Drawing.Size(1200, 800)
    }

    # 4K DPI awareness
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

    # Dark theme for high refresh displays
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.ForeColor = [System.Drawing.Color]::White

    # High refresh rate optimization
    $form.SetStyle([System.Windows.Forms.ControlStyles]::AllPaintingInWmPaint, $true)
    $form.SetStyle([System.Windows.Forms.ControlStyles]::UserPaint, $true)
    $form.SetStyle([System.Windows.Forms.ControlStyles]::DoubleBuffer, $true)

    return $form
}

# Create WebView2 control or fallback
function New-WebViewControl {
    param($Form)

    $webViewAvailable = Import-WebView2Assemblies

    if ($webViewAvailable) {
        try {
            # Try to create WebView2 control
            $webView = New-Object Microsoft.Web.WebView2.WinForms.WebView2
            $webView.Dock = [System.Windows.Forms.DockStyle]::Fill

            Write-Host "✅ Using WebView2 (Microsoft Edge engine)" -ForegroundColor Green
            return $webView
        }
        catch {
            Write-Host "⚠️  WebView2 creation failed, using fallback" -ForegroundColor Yellow
        }
    }

    # Fallback to WebBrowser control
    Write-Host "ℹ️  Using WebBrowser fallback (IE engine)" -ForegroundColor Cyan
    $webBrowser = New-Object System.Windows.Forms.WebBrowser
    $webBrowser.Dock = [System.Windows.Forms.DockStyle]::Fill
    $webBrowser.ScriptErrorsSuppressed = $true
    $webBrowser.WebBrowserShortcutsEnabled = $true
    $webBrowser.IsWebBrowserContextMenuEnabled = $true

    # Force latest IE mode for better compatibility
    $webBrowser.DocumentCompleted.Add({
        $this.Document.Window.DomWindow.execScript("document.documentMode=11", "JavaScript")
    })

    return $webBrowser
}

# Set up JavaScript bridge for PowerShell integration
function Setup-PowerShellBridge {
    param($WebView, $Form)

    if ($WebView.GetType().Name -eq "WebView2") {
        # WebView2 JavaScript bridge
        $WebView.add_NavigationCompleted({
            param($sender, $args)

            if ($global:RawrXDWebView.Debug) {
                Write-Host "🔗 Setting up PowerShell bridge..." -ForegroundColor Cyan
            }

            # Inject PowerShell bridge
            $jsCode = @"
window.PowerShellBridge = {
    executeCommand: function(command) {
        console.log('PowerShell Command:', command);
        window.chrome.webview.postMessage({
            type: 'powershell-command',
            command: command
        });
    },

    openFile: function() {
        window.chrome.webview.postMessage({
            type: 'open-file-dialog'
        });
    },

    saveFile: function(content, filename) {
        window.chrome.webview.postMessage({
            type: 'save-file',
            content: content,
            filename: filename
        });
    },

    getSystemInfo: function() {
        window.chrome.webview.postMessage({
            type: 'system-info'
        });
    },

    analyzeWithOllama: function(code, language) {
        window.chrome.webview.postMessage({
            type: 'ollama-analyze',
            code: code,
            language: language
        });
    }
};

// Override the IDE's backend calls to use PowerShell
if (window.chatWithAI) {
    window.originalChatWithAI = window.chatWithAI;
    window.chatWithAI = function(message) {
        window.PowerShellBridge.executeCommand('ollama run llama3.2 "' + message + '"');
    };
}

console.log('🚀 PowerShell Bridge Ready!');
"@

            try {
                $WebView.ExecuteScriptAsync($jsCode)
            }
            catch {
                Write-Host "⚠️  Failed to inject PowerShell bridge: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        })

        # Handle messages from JavaScript
        $WebView.add_WebMessageReceived({
            param($sender, $args)

            try {
                $message = $args.TryGetWebMessageAsString()
                $data = $message | ConvertFrom-Json

                if ($global:RawrXDWebView.Debug) {
                    Write-Host "📨 Received from JS: $($data.type)" -ForegroundColor Yellow
                }

                switch ($data.type) {
                    "powershell-command" {
                        $result = Invoke-PowerShellCommand -Command $data.command
                        $WebView.PostWebMessageAsString((@{
                            type = "powershell-result"
                            result = $result
                        } | ConvertTo-Json -Depth 5))
                    }

                    "open-file-dialog" {
                        $result = Show-OpenFileDialog
                        if ($result) {
                            $content = Get-Content $result -Raw -ErrorAction SilentlyContinue
                            $WebView.PostWebMessageAsString((@{
                                type = "file-opened"
                                filename = Split-Path $result -Leaf
                                path = $result
                                content = $content
                            } | ConvertTo-Json -Depth 5))
                        }
                    }

                    "save-file" {
                        Save-FileContent -Content $data.content -Filename $data.filename
                    }

                    "system-info" {
                        $systemInfo = Get-SystemInfo
                        $WebView.PostWebMessageAsString((@{
                            type = "system-info-result"
                            data = $systemInfo
                        } | ConvertTo-Json -Depth 5))
                    }

                    "ollama-analyze" {
                        $result = Invoke-OllamaAnalysis -Code $data.code -Language $data.language
                        $WebView.PostWebMessageAsString((@{
                            type = "ollama-result"
                            result = $result
                        } | ConvertTo-Json -Depth 5))
                    }
                }
            }
            catch {
                Write-Host "❌ Error handling JS message: $($_.Exception.Message)" -ForegroundColor Red
            }
        })
    }
    else {
        # WebBrowser control bridge (limited)
        $WebView.add_DocumentCompleted({
            param($sender, $args)

            if ($sender.Document) {
                $sender.Document.InvokeScript("eval", @("
                    window.PowerShellBridge = {
                        executeCommand: function(command) {
                            alert('PowerShell: ' + command);
                        }
                    };
                    console.log('PowerShell Bridge (Limited) Ready!');
                "))
            }
        })
    }
}

# PowerShell backend functions
function Invoke-PowerShellCommand {
    param([string]$Command)

    try {
        if ($global:RawrXDWebView.Debug) {
            Write-Host "🔧 Executing: $Command" -ForegroundColor Magenta
        }

        # Safety check - only allow safe commands
        $safeCommands = @(
            "Get-Date", "Get-Location", "Get-ChildItem", "Get-Process",
            "Get-Service", "Get-ComputerInfo", "Test-Path", "Get-Content",
            "ollama", "git"
        )

        $commandBase = ($Command -split " ")[0]
        if ($commandBase -in $safeCommands -or $Command.StartsWith("ollama ")) {
            $result = Invoke-Expression $Command | Out-String
            return $result
        }
        else {
            return "Command not allowed: $commandBase"
        }
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Show-OpenFileDialog {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Title = "Open File"
    $openDialog.Filter = "All Files (*.*)|*.*|Code Files (*.ps1;*.py;*.js;*.html;*.css)|*.ps1;*.py;*.js;*.html;*.css"
    $openDialog.FilterIndex = 2

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $openDialog.FileName
    }
    return $null
}

function Save-FileContent {
    param([string]$Content, [string]$Filename)

    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Title = "Save File"
        $saveDialog.FileName = $Filename
        $saveDialog.Filter = "All Files (*.*)|*.*|Code Files (*.ps1;*.py;*.js;*.html;*.css)|*.ps1;*.py;*.js;*.html;*.css"

        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $Content | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            Write-Host "✅ File saved: $($saveDialog.FileName)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "❌ Error saving file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-SystemInfo {
    return @{
        OS = (Get-ComputerInfo).WindowsProductName
        PowerShell = $PSVersionTable.PSVersion.ToString()
        .NET = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
        Resolution = "$([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width)x$([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)"
        Cores = (Get-ComputerInfo).CsProcessors.Count
        Memory = [math]::Round((Get-ComputerInfo).CsTotalPhysicalMemory / 1GB, 1)
    }
}

function Invoke-OllamaAnalysis {
    param([string]$Code, [string]$Language)

    try {
        $prompt = "Analyze this $Language code and provide insights: `n$Code"
        $result = ollama run llama3.2 $prompt 2>$null
        return $result
    }
    catch {
        return "Ollama not available or error: $($_.Exception.Message)"
    }
}

# Main application startup
function Start-WebViewIDE {
    param(
        [string]$HtmlPath,
        [int]$Width,
        [int]$Height,
        [bool]$FullScreen,
        [bool]$Debug
    )

    Write-Host "🚀 Starting RawrXD WebView2 IDE..." -ForegroundColor Cyan
    Write-Host "📊 Target Resolution: ${Width}x${Height}" -ForegroundColor Yellow
    Write-Host "📄 HTML Source: $HtmlPath" -ForegroundColor Yellow

    # Enable visual styles for 4K displays
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

    # Create optimized form
    $form = New-OptimizedForm -Width $Width -Height $Height -FullScreen $FullScreen
    $global:RawrXDWebView.Form = $form

    # Create web view control
    $webView = New-WebViewControl -Form $form
    $global:RawrXDWebView.WebView = $webView

    # Set up PowerShell bridge
    Setup-PowerShellBridge -WebView $webView -Form $form

    # Add web view to form
    $form.Controls.Add($webView)

    # Load the HTML IDE
    if (Test-Path $HtmlPath) {
        $uri = "file:///$($HtmlPath.Replace('\', '/'))"
        Write-Host "🌐 Loading IDE from: $uri" -ForegroundColor Green

        if ($webView.GetType().Name -eq "WebView2") {
            $webView.NavigateToString((Get-Content $HtmlPath -Raw))
        }
        else {
            $webView.Navigate($uri)
        }
    }
    else {
        Write-Host "❌ HTML file not found: $HtmlPath" -ForegroundColor Red

        # Create a simple fallback interface
        $fallbackHtml = @"
<!DOCTYPE html>
<html><head><title>RawrXD WebView2</title>
<style>body{background:#1e1e1e;color:#fff;font-family:monospace;padding:20px;}</style>
</head><body>
<h1>🚀 RawrXD WebView2 IDE</h1>
<p>HTML file not found: $HtmlPath</p>
<p>PowerShell Backend Status: ✅ Active</p>
<button onclick="PowerShellBridge.executeCommand('Get-Date')">Test PowerShell Bridge</button>
<div id="output" style="background:#2d2d2d;padding:10px;margin-top:10px;border-radius:5px;"></div>
</body></html>
"@

        if ($webView.GetType().Name -eq "WebView2") {
            $webView.NavigateToString($fallbackHtml)
        }
        else {
            $tempFile = [System.IO.Path]::GetTempFileName() + ".html"
            $fallbackHtml | Out-File $tempFile -Encoding UTF8
            $webView.Navigate($tempFile)
        }
    }

    # Form event handlers
    $form.add_FormClosing({
        Write-Host "👋 Shutting down WebView2 IDE..." -ForegroundColor Yellow
        if ($global:RawrXDWebView.WebView) {
            $global:RawrXDWebView.WebView.Dispose()
        }
    })

    $form.add_Shown({
        Write-Host "✅ WebView2 IDE is ready!" -ForegroundColor Green
        $global:RawrXDWebView.IsInitialized = $true
    })

    # Handle high DPI scaling
    $form.add_DpiChanged({
        if ($global:RawrXDWebView.Debug) {
            Write-Host "🖥️  DPI changed, optimizing for high-resolution display" -ForegroundColor Cyan
        }
    })

    # Show the form
    Write-Host "🎯 Launching IDE optimized for 4K @ 160Hz..." -ForegroundColor Magenta
    [System.Windows.Forms.Application]::Run($form)
}

# Startup checks and launch
try {
    # Verify HTML file exists
    if (-not (Test-Path $HtmlPath)) {
        Write-Host "⚠️  HTML file not found: $HtmlPath" -ForegroundColor Yellow
        Write-Host "📁 Available HTML files:" -ForegroundColor Cyan
        Get-ChildItem "D:\HTML-Projects\*.html" | ForEach-Object {
            Write-Host "   - $($_.Name)" -ForegroundColor White
        }
        Write-Host "`n💡 Using fallback interface..." -ForegroundColor Yellow
    }

    # Launch the hybrid IDE
    Start-WebViewIDE -HtmlPath $HtmlPath -Width $Width -Height $Height -FullScreen $FullScreen.IsPresent -Debug $Debug.IsPresent
}
catch {
    Write-Host "❌ Critical error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
finally {
    Write-Host "👋 RawrXD WebView2 session ended" -ForegroundColor Yellow
}
