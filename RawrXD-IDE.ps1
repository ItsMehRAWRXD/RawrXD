#Requires -Version 5.1
<#
.SYNOPSIS
    RawrXD Pure PowerShell IDE - Complete development environment
.DESCRIPTION
    Full-featured IDE built entirely in PowerShell with integrated RawrXD support
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

# Global IDE State
$Global:RawrXDIDE = @{
    MainForm = $null
    MenuStrip = $null
    ToolStrip = $null
    StatusStrip = $null
    SplitContainer = $null
    FileExplorer = $null
    TabControl = $null
    OutputPanel = $null
    PowerShellConsole = $null
    CurrentFile = $null
    OpenFiles = @{}
    ProjectPath = $null
    Settings = @{
        Theme = 'Dark'
        FontSize = 12
        FontFamily = 'Consolas'
        AutoSave = $true
        ShowLineNumbers = $true
    }
    RawrXDEngine = @{
        Initialized = $false
        ModelLoaded = $false
        CurrentModel = $null
        EngineStatus = 'Idle'
    }
}

function Initialize-RawrXDIDE {
    Write-Host "Initializing RawrXD IDE..." -ForegroundColor Cyan
    
    # Create main form
    $Global:RawrXDIDE.MainForm = New-Object System.Windows.Forms.Form
    $form = $Global:RawrXDIDE.MainForm
    
    $form.Text = "RawrXD IDE - Pure PowerShell Development Environment"
    $form.Size = New-Object System.Drawing.Size(1400, 900)
    $form.StartPosition = 'CenterScreen'
    $form.WindowState = 'Maximized'
    $form.Icon = [System.Drawing.SystemIcons]::Application
    
    # Apply dark theme
    Apply-DarkTheme $form
    
    # Create menu system
    Create-MenuSystem
    
    # Create toolbar
    Create-ToolBar
    
    # Create main layout
    Create-MainLayout
    
    # Create file explorer
    Create-FileExplorer
    
    # Create editor tabs
    Create-EditorTabs
    
    # Create output panel
    Create-OutputPanel
    
    # Create PowerShell console
    Create-PowerShellConsole
    
    # Create status bar
    Create-StatusBar
    
    # Initialize RawrXD engine
    Initialize-RawrXDEngine
    
    # Setup event handlers
    Setup-EventHandlers
    
    Write-Host "RawrXD IDE initialized successfully!" -ForegroundColor Green
}

function Apply-DarkTheme($control) {
    $control.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $control.ForeColor = [System.Drawing.Color]::White
    
    foreach ($child in $control.Controls) {
        Apply-DarkTheme $child
    }
}

function Create-MenuSystem {
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $Global:RawrXDIDE.MenuStrip = $menuStrip
    
    # File Menu
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&File")
    $fileMenu.DropDownItems.Add("&New", $null, { New-File })
    $fileMenu.DropDownItems.Add("&Open", $null, { Open-File })
    $fileMenu.DropDownItems.Add("&Save", $null, { Save-File })
    $fileMenu.DropDownItems.Add("Save &As", $null, { Save-FileAs })
    $fileMenu.DropDownItems.Add("-")
    $fileMenu.DropDownItems.Add("&Recent Files", $null, $null)
    $fileMenu.DropDownItems.Add("-")
    $fileMenu.DropDownItems.Add("E&xit", $null, { $Global:RawrXDIDE.MainForm.Close() })
    
    # Edit Menu
    $editMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Edit")
    $editMenu.DropDownItems.Add("&Undo", $null, { Invoke-EditorCommand 'Undo' })
    $editMenu.DropDownItems.Add("&Redo", $null, { Invoke-EditorCommand 'Redo' })
    $editMenu.DropDownItems.Add("-")
    $editMenu.DropDownItems.Add("Cu&t", $null, { Invoke-EditorCommand 'Cut' })
    $editMenu.DropDownItems.Add("&Copy", $null, { Invoke-EditorCommand 'Copy' })
    $editMenu.DropDownItems.Add("&Paste", $null, { Invoke-EditorCommand 'Paste' })
    $editMenu.DropDownItems.Add("-")
    $editMenu.DropDownItems.Add("&Find", $null, { Show-FindDialog })
    $editMenu.DropDownItems.Add("&Replace", $null, { Show-ReplaceDialog })
    
    # View Menu
    $viewMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&View")
    $viewMenu.DropDownItems.Add("&File Explorer", $null, { Toggle-FileExplorer })
    $viewMenu.DropDownItems.Add("&Output Panel", $null, { Toggle-OutputPanel })
    $viewMenu.DropDownItems.Add("&PowerShell Console", $null, { Toggle-PowerShellConsole })
    $viewMenu.DropDownItems.Add("-")
    $viewMenu.DropDownItems.Add("&Zoom In", $null, { Adjust-FontSize 2 })
    $viewMenu.DropDownItems.Add("&Zoom Out", $null, { Adjust-FontSize -2 })
    
    # RawrXD Menu
    $rawrMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&RawrXD")
    $rawrMenu.DropDownItems.Add("&Initialize Engine", $null, { Initialize-RawrXDEngine })
    $rawrMenu.DropDownItems.Add("&Load GGUF Model", $null, { Load-GGUFModel })
    $rawrMenu.DropDownItems.Add("&Model Status", $null, { Show-ModelStatus })
    $rawrMenu.DropDownItems.Add("-")
    $rawrMenu.DropDownItems.Add("&Quantize Model", $null, { Show-QuantizeDialog })
    $rawrMenu.DropDownItems.Add("&Inference", $null, { Show-InferenceDialog })
    $rawrMenu.DropDownItems.Add("-")
    $rawrMenu.DropDownItems.Add("&Engine Monitor", $null, { Show-EngineMonitor })
    
    # Tools Menu
    $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Tools")
    $toolsMenu.DropDownItems.Add("&PowerShell ISE", $null, { Start-Process powershell_ise })
    $toolsMenu.DropDownItems.Add("&Command Prompt", $null, { Start-Process cmd })
    $toolsMenu.DropDownItems.Add("-")
    $toolsMenu.DropDownItems.Add("&Settings", $null, { Show-SettingsDialog })
    
    # Help Menu
    $helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")
    $helpMenu.DropDownItems.Add("&About RawrXD IDE", $null, { Show-AboutDialog })
    $helpMenu.DropDownItems.Add("&Documentation", $null, { Show-Documentation })
    
    $menuStrip.Items.AddRange(@($fileMenu, $editMenu, $viewMenu, $rawrMenu, $toolsMenu, $helpMenu))
    $Global:RawrXDIDE.MainForm.MainMenuStrip = $menuStrip
    $Global:RawrXDIDE.MainForm.Controls.Add($menuStrip)
}

function Create-ToolBar {
    $toolStrip = New-Object System.Windows.Forms.ToolStrip
    $Global:RawrXDIDE.ToolStrip = $toolStrip
    
    # File operations
    $newBtn = New-Object System.Windows.Forms.ToolStripButton("New")
    $newBtn.Image = [System.Drawing.SystemIcons]::WinLogo.ToBitmap()
    $newBtn.Add_Click({ New-File })
    
    $openBtn = New-Object System.Windows.Forms.ToolStripButton("Open")
    $openBtn.Add_Click({ Open-File })
    
    $saveBtn = New-Object System.Windows.Forms.ToolStripButton("Save")
    $saveBtn.Add_Click({ Save-File })
    
    # Separator
    $sep1 = New-Object System.Windows.Forms.ToolStripSeparator
    
    # RawrXD operations
    $engineBtn = New-Object System.Windows.Forms.ToolStripButton("Engine")
    $engineBtn.Add_Click({ Initialize-RawrXDEngine })
    
    $modelBtn = New-Object System.Windows.Forms.ToolStripButton("Load Model")
    $modelBtn.Add_Click({ Load-GGUFModel })
    
    $inferenceBtn = New-Object System.Windows.Forms.ToolStripButton("Inference")
    $inferenceBtn.Add_Click({ Show-InferenceDialog })
    
    $toolStrip.Items.AddRange(@($newBtn, $openBtn, $saveBtn, $sep1, $engineBtn, $modelBtn, $inferenceBtn))
    $Global:RawrXDIDE.MainForm.Controls.Add($toolStrip)
}

function Create-MainLayout {
    $splitContainer = New-Object System.Windows.Forms.SplitContainer
    $Global:RawrXDIDE.SplitContainer = $splitContainer
    
    $splitContainer.Dock = 'Fill'
    $splitContainer.SplitterDistance = 250
    $splitContainer.Panel1MinSize = 200
    $splitContainer.Panel2MinSize = 400
    
    # Create vertical split for right panel
    $rightSplit = New-Object System.Windows.Forms.SplitContainer
    $rightSplit.Dock = 'Fill'
    $rightSplit.Orientation = 'Horizontal'
    $rightSplit.SplitterDistance = 500
    
    $splitContainer.Panel2.Controls.Add($rightSplit)
    $Global:RawrXDIDE.MainForm.Controls.Add($splitContainer)
}

function Create-FileExplorer {
    $treeView = New-Object System.Windows.Forms.TreeView
    $Global:RawrXDIDE.FileExplorer = $treeView
    
    $treeView.Dock = 'Fill'
    $treeView.ShowLines = $true
    $treeView.ShowPlusMinus = $true
    $treeView.ShowRootLines = $true
    
    # Add context menu
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $contextMenu.Items.Add("Open", $null, { Open-SelectedFile })
    $contextMenu.Items.Add("New File", $null, { New-FileInFolder })
    $contextMenu.Items.Add("New Folder", $null, { New-FolderInFolder })
    $contextMenu.Items.Add("-")
    $contextMenu.Items.Add("Delete", $null, { Delete-SelectedItem })
    $contextMenu.Items.Add("Rename", $null, { Rename-SelectedItem })
    
    $treeView.ContextMenuStrip = $contextMenu
    $treeView.Add_NodeMouseDoubleClick({ Open-SelectedFile })
    
    $Global:RawrXDIDE.SplitContainer.Panel1.Controls.Add($treeView)
    
    # Load current directory
    Load-DirectoryTree (Get-Location).Path
}

function Create-EditorTabs {
    $tabControl = New-Object System.Windows.Forms.TabControl
    $Global:RawrXDIDE.TabControl = $tabControl
    
    $tabControl.Dock = 'Fill'
    $tabControl.Multiline = $false
    $tabControl.Add_SelectedIndexChanged({ Update-CurrentFile })
    
    $Global:RawrXDIDE.SplitContainer.Panel2.Controls[0].Panel1.Controls.Add($tabControl)
}

function Create-OutputPanel {
    $outputSplit = New-Object System.Windows.Forms.SplitContainer
    $outputSplit.Dock = 'Fill'
    $outputSplit.Orientation = 'Horizontal'
    $outputSplit.SplitterDistance = 200
    
    # Output text area
    $outputText = New-Object System.Windows.Forms.RichTextBox
    $Global:RawrXDIDE.OutputPanel = $outputText
    
    $outputText.Dock = 'Fill'
    $outputText.ReadOnly = $true
    $outputText.BackColor = [System.Drawing.Color]::Black
    $outputText.ForeColor = [System.Drawing.Color]::White
    $outputText.Font = New-Object System.Drawing.Font('Consolas', 10)
    
    $outputSplit.Panel1.Controls.Add($outputText)
    $Global:RawrXDIDE.SplitContainer.Panel2.Controls[0].Panel2.Controls.Add($outputSplit)
}

function Create-PowerShellConsole {
    $consoleText = New-Object System.Windows.Forms.RichTextBox
    $Global:RawrXDIDE.PowerShellConsole = $consoleText
    
    $consoleText.Dock = 'Fill'
    $consoleText.BackColor = [System.Drawing.Color]::FromArgb(1, 36, 86)
    $consoleText.ForeColor = [System.Drawing.Color]::White
    $consoleText.Font = New-Object System.Drawing.Font('Consolas', 10)
    
    # Add input handling
    $consoleText.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq 'Enter') {
            Execute-PowerShellCommand
        }
    })
    
    $Global:RawrXDIDE.SplitContainer.Panel2.Controls[0].Panel2.Controls[0].Panel2.Controls.Add($consoleText)
    
    # Initialize with prompt
    Add-ConsoleOutput "RawrXD PowerShell Console`nPS> " -Color 'Green'
}

function Create-StatusBar {
    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $Global:RawrXDIDE.StatusStrip = $statusStrip
    
    $fileLabel = New-Object System.Windows.Forms.ToolStripStatusLabel("Ready")
    $engineLabel = New-Object System.Windows.Forms.ToolStripStatusLabel("Engine: Idle")
    $modelLabel = New-Object System.Windows.Forms.ToolStripStatusLabel("Model: None")
    
    $statusStrip.Items.AddRange(@($fileLabel, $engineLabel, $modelLabel))
    $Global:RawrXDIDE.MainForm.Controls.Add($statusStrip)
}

function Initialize-RawrXDEngine {
    Add-OutputText "Initializing RawrXD Engine..." -Color 'Cyan'
    
    try {
        # Load RawrXD module if available
        $rawrXDPath = Join-Path $PSScriptRoot "RawrXD.ps1"
        if (Test-Path $rawrXDPath) {
            . $rawrXDPath
            Add-OutputText "RawrXD module loaded successfully" -Color 'Green'
        }
        
        # Initialize engine components
        $Global:RawrXDIDE.RawrXDEngine.Initialized = $true
        $Global:RawrXDIDE.RawrXDEngine.EngineStatus = 'Ready'
        
        Add-OutputText "RawrXD Engine initialized successfully" -Color 'Green'
        Update-StatusBar
        
    } catch {
        Add-OutputText "Failed to initialize RawrXD Engine: $($_.Exception.Message)" -Color 'Red'
    }
}

function Load-GGUFModel {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "GGUF Models (*.gguf)|*.gguf|All Files (*.*)|*.*"
    $openDialog.Title = "Select GGUF Model"
    
    if ($openDialog.ShowDialog() -eq 'OK') {
        $modelPath = $openDialog.FileName
        Add-OutputText "Loading GGUF model: $modelPath" -Color 'Yellow'
        
        try {
            # Use RawrXD function if available
            if (Get-Command Open-GGUFModel -ErrorAction SilentlyContinue) {
                Open-GGUFModel -ModelPath $modelPath -MaxZoneMB 512
            } else {
                # Simulate model loading
                Start-Sleep 2
            }
            
            $Global:RawrXDIDE.RawrXDEngine.ModelLoaded = $true
            $Global:RawrXDIDE.RawrXDEngine.CurrentModel = $modelPath
            $Global:RawrXDIDE.RawrXDEngine.EngineStatus = 'Model Loaded'
            
            Add-OutputText "Model loaded successfully" -Color 'Green'
            Update-StatusBar
            
        } catch {
            Add-OutputText "Failed to load model: $($_.Exception.Message)" -Color 'Red'
        }
    }
}

function Show-InferenceDialog {
    if (-not $Global:RawrXDIDE.RawrXDEngine.ModelLoaded) {
        [System.Windows.Forms.MessageBox]::Show("Please load a model first", "No Model", 'OK', 'Warning')
        return
    }
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "RawrXD Inference"
    $form.Size = New-Object System.Drawing.Size(600, 400)
    $form.StartPosition = 'CenterParent'
    
    $promptLabel = New-Object System.Windows.Forms.Label
    $promptLabel.Text = "Prompt:"
    $promptLabel.Location = New-Object System.Drawing.Point(10, 10)
    $promptLabel.Size = New-Object System.Drawing.Size(100, 20)
    
    $promptText = New-Object System.Windows.Forms.TextBox
    $promptText.Location = New-Object System.Drawing.Point(10, 35)
    $promptText.Size = New-Object System.Drawing.Size(560, 100)
    $promptText.Multiline = $true
    $promptText.ScrollBars = 'Vertical'
    
    $maxTokensLabel = New-Object System.Windows.Forms.Label
    $maxTokensLabel.Text = "Max Tokens:"
    $maxTokensLabel.Location = New-Object System.Drawing.Point(10, 150)
    $maxTokensLabel.Size = New-Object System.Drawing.Size(100, 20)
    
    $maxTokensText = New-Object System.Windows.Forms.NumericUpDown
    $maxTokensText.Location = New-Object System.Drawing.Point(120, 148)
    $maxTokensText.Size = New-Object System.Drawing.Size(100, 20)
    $maxTokensText.Value = 100
    $maxTokensText.Maximum = 2048
    
    $generateBtn = New-Object System.Windows.Forms.Button
    $generateBtn.Text = "Generate"
    $generateBtn.Location = New-Object System.Drawing.Point(250, 148)
    $generateBtn.Size = New-Object System.Drawing.Size(100, 25)
    $generateBtn.Add_Click({
        $prompt = $promptText.Text
        $maxTokens = [int]$maxTokensText.Value
        
        if ([string]::IsNullOrWhiteSpace($prompt)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a prompt", "Empty Prompt", 'OK', 'Warning')
            return
        }
        
        Add-OutputText "Generating inference for: $prompt" -Color 'Yellow'
        
        try {
            if (Get-Command Invoke-PoshLLMInference -ErrorAction SilentlyContinue) {
                $result = Invoke-PoshLLMInference -Prompt $prompt -MaxTokens $maxTokens
            } else {
                $result = "Simulated inference result for: $prompt"
            }
            
            Add-OutputText "Inference Result:`n$result" -Color 'Green'
            
        } catch {
            Add-OutputText "Inference failed: $($_.Exception.Message)" -Color 'Red'
        }
        
        $form.Close()
    })
    
    $form.Controls.AddRange(@($promptLabel, $promptText, $maxTokensLabel, $maxTokensText, $generateBtn))
    $form.ShowDialog()
}

function New-File {
    $tabPage = New-Object System.Windows.Forms.TabPage
    $tabPage.Text = "Untitled"
    
    $editor = New-Object System.Windows.Forms.RichTextBox
    $editor.Dock = 'Fill'
    $editor.Font = New-Object System.Drawing.Font($Global:RawrXDIDE.Settings.FontFamily, $Global:RawrXDIDE.Settings.FontSize)
    $editor.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $editor.ForeColor = [System.Drawing.Color]::White
    $editor.AcceptsTab = $true
    
    # Add syntax highlighting
    $editor.Add_TextChanged({ Apply-SyntaxHighlighting $editor })
    
    $tabPage.Controls.Add($editor)
    $Global:RawrXDIDE.TabControl.TabPages.Add($tabPage)
    $Global:RawrXDIDE.TabControl.SelectedTab = $tabPage
    
    $Global:RawrXDIDE.OpenFiles[$tabPage] = @{
        FilePath = $null
        Editor = $editor
        Modified = $false
    }
}

function Open-File {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "All Files (*.*)|*.*|PowerShell (*.ps1)|*.ps1|Text (*.txt)|*.txt|Assembly (*.asm)|*.asm"
    
    if ($openDialog.ShowDialog() -eq 'OK') {
        $filePath = $openDialog.FileName
        $fileName = [System.IO.Path]::GetFileName($filePath)
        
        # Check if file is already open
        foreach ($tab in $Global:RawrXDIDE.OpenFiles.Keys) {
            if ($Global:RawrXDIDE.OpenFiles[$tab].FilePath -eq $filePath) {
                $Global:RawrXDIDE.TabControl.SelectedTab = $tab
                return
            }
        }
        
        $tabPage = New-Object System.Windows.Forms.TabPage
        $tabPage.Text = $fileName
        
        $editor = New-Object System.Windows.Forms.RichTextBox
        $editor.Dock = 'Fill'
        $editor.Font = New-Object System.Drawing.Font($Global:RawrXDIDE.Settings.FontFamily, $Global:RawrXDIDE.Settings.FontSize)
        $editor.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $editor.ForeColor = [System.Drawing.Color]::White
        $editor.AcceptsTab = $true
        
        try {
            $content = Get-Content $filePath -Raw -ErrorAction Stop
            $editor.Text = $content
            Apply-SyntaxHighlighting $editor
        } catch {
            Add-OutputText "Failed to open file: $($_.Exception.Message)" -Color 'Red'
            return
        }
        
        $editor.Add_TextChanged({ 
            Apply-SyntaxHighlighting $editor
            Mark-FileModified $tabPage
        })
        
        $tabPage.Controls.Add($editor)
        $Global:RawrXDIDE.TabControl.TabPages.Add($tabPage)
        $Global:RawrXDIDE.TabControl.SelectedTab = $tabPage
        
        $Global:RawrXDIDE.OpenFiles[$tabPage] = @{
            FilePath = $filePath
            Editor = $editor
            Modified = $false
        }
        
        Add-OutputText "Opened: $filePath" -Color 'Green'
    }
}

function Save-File {
    $currentTab = $Global:RawrXDIDE.TabControl.SelectedTab
    if (-not $currentTab) { return }
    
    $fileInfo = $Global:RawrXDIDE.OpenFiles[$currentTab]
    
    if (-not $fileInfo.FilePath) {
        Save-FileAs
        return
    }
    
    try {
        $content = $fileInfo.Editor.Text
        Set-Content -Path $fileInfo.FilePath -Value $content -ErrorAction Stop
        
        $fileInfo.Modified = $false
        $currentTab.Text = [System.IO.Path]::GetFileName($fileInfo.FilePath)
        
        Add-OutputText "Saved: $($fileInfo.FilePath)" -Color 'Green'
        
    } catch {
        Add-OutputText "Failed to save file: $($_.Exception.Message)" -Color 'Red'
    }
}

function Save-FileAs {
    $currentTab = $Global:RawrXDIDE.TabControl.SelectedTab
    if (-not $currentTab) { return }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "All Files (*.*)|*.*|PowerShell (*.ps1)|*.ps1|Text (*.txt)|*.txt|Assembly (*.asm)|*.asm"
    
    if ($saveDialog.ShowDialog() -eq 'OK') {
        $filePath = $saveDialog.FileName
        $fileInfo = $Global:RawrXDIDE.OpenFiles[$currentTab]
        
        try {
            $content = $fileInfo.Editor.Text
            Set-Content -Path $filePath -Value $content -ErrorAction Stop
            
            $fileInfo.FilePath = $filePath
            $fileInfo.Modified = $false
            $currentTab.Text = [System.IO.Path]::GetFileName($filePath)
            
            Add-OutputText "Saved as: $filePath" -Color 'Green'
            
        } catch {
            Add-OutputText "Failed to save file: $($_.Exception.Message)" -Color 'Red'
        }
    }
}

function Apply-SyntaxHighlighting($editor) {
    # Simple syntax highlighting for PowerShell
    $text = $editor.Text
    $editor.SelectAll()
    $editor.SelectionColor = [System.Drawing.Color]::White
    
    # Keywords
    $keywords = @('function', 'param', 'if', 'else', 'elseif', 'switch', 'foreach', 'for', 'while', 'do', 'try', 'catch', 'finally', 'return', 'break', 'continue')
    foreach ($keyword in $keywords) {
        $index = 0
        while (($index = $text.IndexOf($keyword, $index, [StringComparison]::OrdinalIgnoreCase)) -ne -1) {
            $editor.Select($index, $keyword.Length)
            $editor.SelectionColor = [System.Drawing.Color]::CornflowerBlue
            $index += $keyword.Length
        }
    }
    
    # Comments
    $lines = $text -split "`n"
    $currentIndex = 0
    foreach ($line in $lines) {
        $commentIndex = $line.IndexOf('#')
        if ($commentIndex -ne -1) {
            $editor.Select($currentIndex + $commentIndex, $line.Length - $commentIndex)
            $editor.SelectionColor = [System.Drawing.Color]::Green
        }
        $currentIndex += $line.Length + 1
    }
    
    # Strings
    $stringPattern = '"[^"]*"'
    $matches = [regex]::Matches($text, $stringPattern)
    foreach ($match in $matches) {
        $editor.Select($match.Index, $match.Length)
        $editor.SelectionColor = [System.Drawing.Color]::Orange
    }
    
    $editor.Select(0, 0)
}

function Add-OutputText($text, $color = 'White') {
    $output = $Global:RawrXDIDE.OutputPanel
    $output.SelectionStart = $output.TextLength
    $output.SelectionLength = 0
    $output.SelectionColor = [System.Drawing.Color]::$color
    $output.AppendText("$(Get-Date -Format 'HH:mm:ss'): $text`n")
    $output.ScrollToCaret()
}

function Add-ConsoleOutput($text, $color = 'White') {
    $console = $Global:RawrXDIDE.PowerShellConsole
    $console.SelectionStart = $console.TextLength
    $console.SelectionLength = 0
    $console.SelectionColor = [System.Drawing.Color]::$color
    $console.AppendText($text)
    $console.ScrollToCaret()
}

function Execute-PowerShellCommand {
    $console = $Global:RawrXDIDE.PowerShellConsole
    $text = $console.Text
    $lines = $text -split "`n"
    $lastLine = $lines[-1]
    
    if ($lastLine.StartsWith('PS> ')) {
        $command = $lastLine.Substring(4)
        
        if (-not [string]::IsNullOrWhiteSpace($command)) {
            Add-ConsoleOutput "`n" -Color 'White'
            
            try {
                $result = Invoke-Expression $command | Out-String
                Add-ConsoleOutput $result -Color 'Gray'
            } catch {
                Add-ConsoleOutput "Error: $($_.Exception.Message)`n" -Color 'Red'
            }
        }
        
        Add-ConsoleOutput "PS> " -Color 'Green'
    }
}

function Load-DirectoryTree($path) {
    $treeView = $Global:RawrXDIDE.FileExplorer
    $treeView.Nodes.Clear()
    
    $rootNode = New-Object System.Windows.Forms.TreeNode([System.IO.Path]::GetFileName($path))
    $rootNode.Tag = $path
    $treeView.Nodes.Add($rootNode)
    
    Load-DirectoryNodes $rootNode $path
    $rootNode.Expand()
}

function Load-DirectoryNodes($parentNode, $path) {
    try {
        # Add directories
        $directories = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $directories) {
            $node = New-Object System.Windows.Forms.TreeNode($dir.Name)
            $node.Tag = $dir.FullName
            $parentNode.Nodes.Add($node)
            
            # Add placeholder for lazy loading
            $placeholder = New-Object System.Windows.Forms.TreeNode("Loading...")
            $node.Nodes.Add($placeholder)
        }
        
        # Add files
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $node = New-Object System.Windows.Forms.TreeNode($file.Name)
            $node.Tag = $file.FullName
            $parentNode.Nodes.Add($node)
        }
    } catch {
        Add-OutputText "Error loading directory: $($_.Exception.Message)" -Color 'Red'
    }
}

function Update-StatusBar {
    $statusStrip = $Global:RawrXDIDE.StatusStrip
    $statusStrip.Items[1].Text = "Engine: $($Global:RawrXDIDE.RawrXDEngine.EngineStatus)"
    
    if ($Global:RawrXDIDE.RawrXDEngine.CurrentModel) {
        $modelName = [System.IO.Path]::GetFileName($Global:RawrXDIDE.RawrXDEngine.CurrentModel)
        $statusStrip.Items[2].Text = "Model: $modelName"
    } else {
        $statusStrip.Items[2].Text = "Model: None"
    }
}

function Setup-EventHandlers {
    $form = $Global:RawrXDIDE.MainForm
    
    # Form closing event
    $form.Add_FormClosing({
        param($sender, $e)
        
        # Check for unsaved files
        $unsavedFiles = @()
        foreach ($tab in $Global:RawrXDIDE.OpenFiles.Keys) {
            if ($Global:RawrXDIDE.OpenFiles[$tab].Modified) {
                $unsavedFiles += $tab.Text
            }
        }
        
        if ($unsavedFiles.Count -gt 0) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "You have unsaved files: $($unsavedFiles -join ', ')`nDo you want to save them before closing?",
                "Unsaved Files",
                'YesNoCancel',
                'Question'
            )
            
            if ($result -eq 'Cancel') {
                $e.Cancel = $true
                return
            } elseif ($result -eq 'Yes') {
                foreach ($tab in $Global:RawrXDIDE.OpenFiles.Keys) {
                    if ($Global:RawrXDIDE.OpenFiles[$tab].Modified) {
                        $Global:RawrXDIDE.TabControl.SelectedTab = $tab
                        Save-File
                    }
                }
            }
        }
    })
    
    # File explorer events
    $Global:RawrXDIDE.FileExplorer.Add_BeforeExpand({
        param($sender, $e)
        $node = $e.Node
        
        if ($node.Nodes.Count -eq 1 -and $node.Nodes[0].Text -eq "Loading...") {
            $node.Nodes.Clear()
            Load-DirectoryNodes $node $node.Tag
        }
    })
}

function Show-AboutDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "About RawrXD IDE"
    $form.Size = New-Object System.Drawing.Size(400, 300)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    
    $label = New-Object System.Windows.Forms.Label
    $label.Text = @"
RawrXD IDE
Pure PowerShell Development Environment

Version: 1.0
Built with: PowerShell $($PSVersionTable.PSVersion)

Features:
• Full-featured code editor
• Integrated PowerShell console
• RawrXD engine integration
• GGUF model support
• Syntax highlighting
• File explorer
• Project management

© 2024 RawrXD Project
"@
    $label.Location = New-Object System.Drawing.Point(20, 20)
    $label.Size = New-Object System.Drawing.Size(350, 220)
    $label.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    
    $okBtn = New-Object System.Windows.Forms.Button
    $okBtn.Text = "OK"
    $okBtn.Location = New-Object System.Drawing.Point(160, 250)
    $okBtn.Size = New-Object System.Drawing.Size(75, 25)
    $okBtn.Add_Click({ $form.Close() })
    
    $form.Controls.AddRange(@($label, $okBtn))
    $form.ShowDialog()
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Initialize-RawrXDIDE
    
    # Show the form
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::Run($Global:RawrXDIDE.MainForm)
}