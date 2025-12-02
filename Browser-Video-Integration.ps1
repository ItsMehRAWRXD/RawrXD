<#
.SYNOPSIS
    RawrXD Browser & Video Integration Demo

.DESCRIPTION
    Demonstrates how to use the RawrXD.Browser and RawrXD.Video modules
    together for autonomous web browsing with video streaming capabilities.

    This script shows real-world integration with the existing RawrXD architecture.

.NOTES
    Requires RawrXD modules to be available in Modules/Modules/ directory
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$DemoMode,
    [Parameter(Mandatory = $false)]
    [string]$BrowserId = "demo-browser"
)

#region Initialization
$ErrorActionPreference = "Stop"

# Set up module paths
$scriptRoot = $PSScriptRoot
$modulesPath = Join-Path $scriptRoot "Modules\Modules"

# Import required modules
$requiredModules = @(
    "RawrXD.Browser",
    "RawrXD.Video",
    "RawrXD.Logging"  # For Write-DevConsole function
)

foreach ($module in $requiredModules) {
    $modulePath = Join-Path $modulesPath "$module.psm1"
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force -ErrorAction Stop
            Write-Host "✅ Imported module: $module" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Failed to import $module : $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "⚠️ Module not found: $modulePath" -ForegroundColor Yellow
    }
}

# Check for Write-DevConsole function
if (-not (Get-Command "Write-DevConsole" -ErrorAction SilentlyContinue)) {
    function Write-DevConsole {
        param($Message, $Level = "INFO")
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "Cyan" }
        }
        Write-Host "[$Level] $Message" -ForegroundColor $color
    }
}

Write-Host "🚀 RawrXD Browser-Video Integration Demo" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan
#endregion

#region Demo Functions
function Show-BrowserCapabilities {
    Write-Host "`n🌐 Browser Module Capabilities:" -ForegroundColor Magenta
    $browserInfo = Get-BrowserInfo
    $browserInfo | Format-List
}

function Show-VideoCapabilities {
    Write-Host "`n🎬 Video Module Capabilities:" -ForegroundColor Magenta
    $videoCaps = Get-VideoCapabilities
    $videoCaps | Format-List
}

function Start-BrowserDemo {
    param([string]$BrowserId)

    Write-Host "`n🌐 Creating Browser Agent..." -ForegroundColor Yellow

    # Create a simple form for the browser
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD Browser Demo"
    $form.Size = [System.Drawing.Size]::new(1024, 768)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    # Create panel for browser
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($panel)

    # Create browser agent
    $browser = New-BrowserAgent -Id $BrowserId -ParentControl $panel

    if (-not $browser) {
        Write-Host "❌ Failed to create browser agent" -ForegroundColor Red
        return
    }

    Write-Host "✅ Browser agent created successfully" -ForegroundColor Green

    # Demo navigation
    Write-Host "🌐 Navigating to YouTube..." -ForegroundColor Yellow
    Invoke-BrowserNavigation -AgentId $BrowserId -Url "https://www.youtube.com"

    # Wait for page to load
    Start-Sleep -Seconds 3

    # Demo video control
    Write-Host "🎬 Attempting to play video..." -ForegroundColor Yellow
    Invoke-BrowserVideoControl -AgentId $BrowserId -Action "Play"

    # Demo screenshot
    $screenshotPath = Join-Path $PSScriptRoot "browser-screenshot.png"
    Write-Host "📸 Taking screenshot..." -ForegroundColor Yellow
    Invoke-BrowserScreenshot -AgentId $BrowserId -OutputPath $screenshotPath

    if (Test-Path $screenshotPath) {
        Write-Host "✅ Screenshot saved: $screenshotPath" -ForegroundColor Green
    }

    # Show form (non-blocking in demo mode)
    if ($DemoMode) {
        Write-Host "📋 Demo mode - browser will close in 10 seconds..." -ForegroundColor Cyan
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 10000  # 10 seconds
        $timer.Add_Tick({
            $form.Close()
            $timer.Stop()
        })
        $timer.Start()
    }

    $form.ShowDialog()
    Write-Host "✅ Browser demo completed" -ForegroundColor Green
}

function Start-VideoDemo {
    Write-Host "`n🎬 Creating Video Stream..." -ForegroundColor Yellow

    # Create a simple form for the video
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD Video Demo"
    $form.Size = [System.Drawing.Size]::new(800, 600)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    # Create panel for video
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($panel)

    # Create video stream
    $videoUrl = "https://sample-videos.com/zip/10/mp4/SampleVideo_1280x720_1mb.mp4"  # Sample video
    $stream = New-VideoStream -Id "demo-video" -Url $videoUrl -ParentControl $panel

    if (-not $stream) {
        Write-Host "❌ Failed to create video stream" -ForegroundColor Red
        return
    }

    Write-Host "✅ Video stream created successfully" -ForegroundColor Green
    Write-Host "🎬 Starting video playback..." -ForegroundColor Yellow

    # Control video playback
    Invoke-VideoControl -StreamId "demo-video" -Action "Play"

    # Demo volume control
    Start-Sleep -Seconds 2
    Write-Host "🔊 Setting volume to 50%..." -ForegroundColor Yellow
    Set-VideoVolume -StreamId "demo-video" -Volume 0.5

    # Demo seeking
    Start-Sleep -Seconds 2
    Write-Host "⏩ Seeking to 10 seconds..." -ForegroundColor Yellow
    Set-VideoPosition -StreamId "demo-video" -Seconds 10

    # Demo pause/resume
    Start-Sleep -Seconds 2
    Write-Host "⏸️ Pausing video..." -ForegroundColor Yellow
    Invoke-VideoControl -StreamId "demo-video" -Action "Pause"

    Start-Sleep -Seconds 2
    Write-Host "▶️ Resuming video..." -ForegroundColor Yellow
    Invoke-VideoControl -StreamId "demo-video" -Action "Play"

    # Get metadata
    $metadata = Get-VideoMetadata -StreamId "demo-video"
    Write-Host "📊 Video metadata:" -ForegroundColor Cyan
    $metadata | Format-List

    # Show form (non-blocking in demo mode)
    if ($DemoMode) {
        Write-Host "📋 Demo mode - video will close in 15 seconds..." -ForegroundColor Cyan
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 15000  # 15 seconds
        $timer.Add_Tick({
            Invoke-VideoControl -StreamId "demo-video" -Action "Stop"
            $form.Close()
            $timer.Stop()
        })
        $timer.Start()
    }

    $form.ShowDialog()
    Write-Host "✅ Video demo completed" -ForegroundColor Green
}

function Start-AgentAutomationDemo {
    Write-Host "`n🤖 Starting Agent Automation Demo..." -ForegroundColor Yellow

    # Create browser agent
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD Agent Automation Demo"
    $form.Size = [System.Drawing.Size]::new(1024, 768)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($panel)

    $browser = New-BrowserAgent -Id "agent-browser" -ParentControl $panel

    # Create automation tasks
    Write-Host "📋 Creating automation tasks..." -ForegroundColor Cyan

    New-AgentTask -Id "nav-youtube" -Type "Navigate" -Parameters @{ Url = "https://www.youtube.com" }
    New-AgentTask -Id "search-videos" -Type "FillForm" -Parameters @{ Selector = "input#search-input"; Value = "PowerShell tutorial" }
    New-AgentTask -Id "click-search" -Type "Click" -Parameters @{ Selector = "button#search-button" }
    New-AgentTask -Id "play-first-video" -Type "PlayVideo" -Parameters @{}

    # Execute automation sequence
    $taskSequence = @("nav-youtube", "search-videos", "click-search", "play-first-video")
    Write-Host "🚀 Executing automation sequence: $($taskSequence -join ' -> ')" -ForegroundColor Green

    Start-AgentAutomation -AgentId "agent-browser" -TaskSequence $taskSequence -Interval 3

    # Show form
    if ($DemoMode) {
        Write-Host "📋 Demo mode - automation will complete in 20 seconds..." -ForegroundColor Cyan
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 20000  # 20 seconds
        $timer.Add_Tick({
            $form.Close()
            $timer.Stop()
        })
        $timer.Start()
    }

    $form.ShowDialog()
    Write-Host "✅ Agent automation demo completed" -ForegroundColor Green
}

function Start-IntegratedDemo {
    Write-Host "`n🎭 Starting Integrated Browser + Video Demo..." -ForegroundColor Yellow

    # Create main form with split panels
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD Integrated Demo"
    $form.Size = [System.Drawing.Size]::new(1400, 800)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

    # Create split container
    $splitContainer = New-Object System.Windows.Forms.SplitContainer
    $splitContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.Orientation = [System.Windows.Forms.Orientation]::Vertical
    $splitContainer.SplitterDistance = 700
    $form.Controls.Add($splitContainer)

    # Browser panel (top)
    $browserPanel = New-Object System.Windows.Forms.Panel
    $browserPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.Panel1.Controls.Add($browserPanel)

    # Video panel (bottom)
    $videoPanel = New-Object System.Windows.Forms.Panel
    $videoPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.Panel2.Controls.Add($videoPanel)

    # Create browser and video components
    Write-Host "🌐 Creating browser agent..." -ForegroundColor Cyan
    $browser = New-BrowserAgent -Id "integrated-browser" -ParentControl $browserPanel

    Write-Host "🎬 Creating video stream..." -ForegroundColor Cyan
    $videoUrl = "https://sample-videos.com/zip/10/mp4/SampleVideo_1280x720_1mb.mp4"
    $video = New-VideoStream -Id "integrated-video" -Url $videoUrl -ParentControl $videoPanel

    # Synchronized playback demo
    Write-Host "🔄 Starting synchronized playback..." -ForegroundColor Green

    # Navigate browser to YouTube
    Invoke-BrowserNavigation -AgentId "integrated-browser" -Url "https://www.youtube.com"

    # Start video playback
    Start-Sleep -Seconds 2
    Invoke-VideoControl -StreamId "integrated-video" -Action "Play"

    # Demonstrate cross-component interaction
    Start-Sleep -Seconds 3
    Write-Host "🎯 Demonstrating cross-component control..." -ForegroundColor Yellow

    # Browser video control
    Invoke-BrowserVideoControl -AgentId "integrated-browser" -Action "Play"

    # Local video control
    Invoke-VideoControl -StreamId "integrated-video" -Action "Pause"

    # Get status from both components
    $browserInfo = Get-BrowserInfo
    $videoStreams = Get-VideoStreams

    Write-Host "📊 System Status:" -ForegroundColor Cyan
    Write-Host "  Active Browsers: $($browserInfo.ActiveAgents.Count)" -ForegroundColor White
    Write-Host "  Active Videos: $($videoStreams.Count)" -ForegroundColor White

    # Show form
    if ($DemoMode) {
        Write-Host "📋 Demo mode - integrated demo will close in 25 seconds..." -ForegroundColor Cyan
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 25000  # 25 seconds
        $timer.Add_Tick({
            Stop-AllVideos
            $form.Close()
            $timer.Stop()
        })
        $timer.Start()
    }

    $form.ShowDialog()
    Write-Host "✅ Integrated demo completed" -ForegroundColor Green
}
#endregion

#region Main Execution
function Show-Menu {
    Write-Host "`n🎮 RawrXD Browser-Video Integration Demo Menu" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan
    Write-Host "1. Show Browser Capabilities"
    Write-Host "2. Show Video Capabilities"
    Write-Host "3. Browser Demo"
    Write-Host "4. Video Demo"
    Write-Host "5. Agent Automation Demo"
    Write-Host "6. Integrated Demo (Browser + Video)"
    Write-Host "7. Run All Demos"
    Write-Host "8. Exit"
    Write-Host "=" * 50 -ForegroundColor Cyan
}

function Invoke-AllDemos {
    Write-Host "`n🎪 Running All Demos..." -ForegroundColor Green

    Show-BrowserCapabilities
    Show-VideoCapabilities

    # Note: GUI demos can't run sequentially in the same process
    Write-Host "`n⚠️ GUI demos must be run individually. Use menu options 3-6." -ForegroundColor Yellow
    Write-Host "💡 Use -DemoMode parameter for automatic demo completion." -ForegroundColor Cyan
}

# Main menu loop
do {
    Show-Menu
    $choice = Read-Host "Select option (1-8)"

    switch ($choice) {
        "1" { Show-BrowserCapabilities }
        "2" { Show-VideoCapabilities }
        "3" { Start-BrowserDemo -BrowserId $BrowserId }
        "4" { Start-VideoDemo }
        "5" { Start-AgentAutomationDemo }
        "6" { Start-IntegratedDemo }
        "7" { Invoke-AllDemos }
        "8" {
            Write-Host "`n👋 Goodbye! Thanks for exploring RawrXD integration." -ForegroundColor Cyan
            break
        }
        default {
            Write-Host "❌ Invalid option. Please select 1-8." -ForegroundColor Red
        }
    }

    if ($choice -ne "8") {
        Read-Host "`nPress Enter to continue..."
    }
} while ($choice -ne "8")

Write-Host "`n🎉 RawrXD Browser-Video Integration Demo Complete!" -ForegroundColor Green
#endregion
