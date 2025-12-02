# RawrXD-UI-TextEditor.psm1 - Text editor component with syntax highlighting
function Initialize-TextEditor {
    try {
        Write-RawrXDLog "Initializing text editor..." -Level INFO -Component "TextEditor"
        $editorPanel = $global:RawrXD.Components.EditorPanel
        if (-not $editorPanel) {
            throw "Editor panel not found"
        }
        # Create editor container with toolbar
        $editorContainer = New-Object System.Windows.Forms.Panel
        $editorContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
        # Create toolbar
        $toolbar = Create-EditorToolbar
        $editorContainer.Controls.Add($toolbar)
        # Create text editor
        $textBox = New-Object System.Windows.Forms.RichTextBox
        $textBox.Dock = [System.Windows.Forms.DockStyle]::Fill
        $textBox.Font = New-Object System.Drawing.Font($global:RawrXD.Settings.UI.FontFamily, $global:RawrXD.Settings.UI.FontSize)
        $textBox.AcceptsTab = $true
        $textBox.WordWrap = $global:RawrXD.Settings.Editor.WordWrap
        $textBox.ShowSelectionMargin = $true
        $textBox.DetectUrls = $false
        $textBox.HideSelection = $false
        # Apply theme
        Apply-EditorTheme -TextBox $textBox
        # Set up editor events
        Setup-EditorEvents -TextBox $textBox
        $editorContainer.Controls.Add($textBox)
        $editorPanel.Controls.Add($editorContainer)
        # Store references
        $global:RawrXD.Components.TextEditor = $textBox
        $global:RawrXD.Components.EditorContainer = $editorContainer
        $global:RawrXD.Components.EditorToolbar = $toolbar
        # Initialize undo/redo system
        $global:RawrXD.Editor = @{
            UndoStack = New-Object System.Collections.Stack
            RedoStack = New-Object System.Collections.Stack
            IsModified = $false
            CurrentFile = $null
            LastSaveTime = $null
            SyntaxTimer = $null
        }
        Write-RawrXDLog "Text editor initialized successfully" -Level SUCCESS -Component "TextEditor"
    }
    catch {
        Write-RawrXDLog "Failed to initialize text editor: $($_.Exception.Message)" -Level ERROR -Component "TextEditor"
        throw
    }
}
function Create-EditorToolbar {
    $toolbar = New-Object System.Windows.Forms.ToolStrip
    $toolbar.Dock = [System.Windows.Forms.DockStyle]::Top
    $toolbar.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    # New button
    $newBtn = New-Object System.Windows.Forms.ToolStripButton
    $newBtn.Text = "New"
    $newBtn.ToolTipText = "Create new file (Ctrl+N)"
    $newBtn.add_Click({ New-EditorFile })
    # Open button
    $openBtn = New-Object System.Windows.Forms.ToolStripButton
    $openBtn.Text = "Open"
    $openBtn.ToolTipText = "Open file (Ctrl+O)"
    $openBtn.add_Click({ Open-EditorFile })
    # Save button
    $saveBtn = New-Object System.Windows.Forms.ToolStripButton
    $saveBtn.Text = "Save"
    $saveBtn.ToolTipText = "Save file (Ctrl+S)"
    $saveBtn.add_Click({ Save-EditorFile })
    # Separator
    $separator1 = New-Object System.Windows.Forms.ToolStripSeparator
    # Undo button
    $undoBtn = New-Object System.Windows.Forms.ToolStripButton
    $undoBtn.Text = "Undo"
    $undoBtn.ToolTipText = "Undo (Ctrl+Z)"
    $undoBtn.add_Click({ Undo-EditorAction })
    # Redo button
    $redoBtn = New-Object System.Windows.Forms.ToolStripButton
    $redoBtn.Text = "Redo"
    $redoBtn.ToolTipText = "Redo (Ctrl+Y)"
    $redoBtn.add_Click({ Redo-EditorAction })
    # Separator
    $separator2 = New-Object System.Windows.Forms.ToolStripSeparator
    # Find button
    $findBtn = New-Object System.Windows.Forms.ToolStripButton
    $findBtn.Text = "Find"
    $findBtn.ToolTipText = "Find (Ctrl+F)"
    $findBtn.add_Click({ Show-EditorFindDialog })
    # Word wrap toggle
    $wrapBtn = New-Object System.Windows.Forms.ToolStripButton
    $wrapBtn.Text = "Wrap"
    $wrapBtn.ToolTipText = "Toggle word wrap"
    $wrapBtn.CheckOnClick = $true
    $wrapBtn.Checked = $global:RawrXD.Settings.Editor.WordWrap
    $wrapBtn.add_Click({ Toggle-WordWrap })
    # Zoom dropdown
    $zoomLabel = New-Object System.Windows.Forms.ToolStripLabel
    $zoomLabel.Text = "Zoom:"
    $zoomCombo = New-Object System.Windows.Forms.ToolStripComboBox
    $zoomCombo.Size = New-Object System.Drawing.Size(60, 25)
    $zoomCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $zoomCombo.Items.AddRange(@("75%", "90%", "100%", "110%", "125%", "150%", "200%"))
    $zoomCombo.SelectedItem = "100%"
    $zoomCombo.add_SelectedIndexChanged({ Set-EditorZoom })
    $toolbar.Items.AddRange(@($newBtn, $openBtn, $saveBtn, $separator1, $undoBtn, $redoBtn, $separator2, $findBtn, $wrapBtn, $zoomLabel, $zoomCombo))
    # Store toolbar references
    $global:RawrXD.Components.EditorButtons = @{
        New = $newBtn
        Open = $openBtn
        Save = $saveBtn
        Undo = $undoBtn
        Redo = $redoBtn
        Find = $findBtn
        WordWrap = $wrapBtn
        Zoom = $zoomCombo
    }
    return $toolbar
}
function Apply-EditorTheme {
    param($TextBox)
    $theme = $global:RawrXD.Settings.UI.Theme
    if ($theme -eq "Dark") {
        $TextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $TextBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
        $TextBox.SelectionBackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    }
    else {
        $TextBox.BackColor = [System.Drawing.Color]::White
        $TextBox.ForeColor = [System.Drawing.Color]::Black
        $TextBox.SelectionBackColor = [System.Drawing.SystemColors]::Highlight
    }
}
function Setup-EditorEvents {
    param($TextBox)
    # Text changed event for syntax highlighting and auto-save
    $TextBox.add_TextChanged({
        $global:RawrXD.Editor.IsModified = $true
        Update-EditorTitle
        # Start syntax highlighting timer
        if ($global:RawrXD.Editor.SyntaxTimer) {
            $global:RawrXD.Editor.SyntaxTimer.Stop()
        }
        $global:RawrXD.Editor.SyntaxTimer = New-Object System.Windows.Forms.Timer
        $global:RawrXD.Editor.SyntaxTimer.Interval = 500
        $global:RawrXD.Editor.SyntaxTimer.add_Tick({
            Apply-SyntaxHighlighting
            $global:RawrXD.Editor.SyntaxTimer.Stop()
        })
        $global:RawrXD.Editor.SyntaxTimer.Start()
    })
    # Selection changed event for position updates
    $TextBox.add_SelectionChanged({
        Update-CursorPosition
    })
    # Key down event for custom shortcuts and auto-indentation
    $TextBox.add_KeyDown({
        param($sender, $e)
        # Handle custom shortcuts
        if ($e.Control) {
            switch ($e.KeyCode) {
                "N" { $e.Handled = $true; New-EditorFile }
                "O" { $e.Handled = $true; Open-EditorFile }
                "S" { $e.Handled = $true; Save-EditorFile }
                "F" { $e.Handled = $true; Show-EditorFindDialog }
                "Z" { $e.Handled = $true; Undo-EditorAction }
                "Y" { $e.Handled = $true; Redo-EditorAction }
            }
        }
        # Handle Enter key for auto-indentation
        if ($e.KeyCode -eq "Enter" -and $global:RawrXD.Settings.Editor.AutoIndent) {
            Handle-AutoIndent -Sender $sender -EventArgs $e
        }
        # Handle Tab key
        if ($e.KeyCode -eq "Tab") {
            Handle-TabKey -Sender $sender -EventArgs $e
        }
    })
    # Drag and drop events
    $TextBox.AllowDrop = $true
    $TextBox.add_DragEnter({
        param($sender, $e)
        if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        }
    })
    $TextBox.add_DragDrop({
        param($sender, $e)
        $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        if ($files.Length -gt 0) {
            Load-FileContent -FilePath $files[0]
        }
    })
}
function New-EditorFile {
    $textBox = $global:RawrXD.Components.TextEditor
    if ($textBox) {
        if ($global:RawrXD.Editor.IsModified) {
            $result = [System.Windows.Forms.MessageBox]::Show("Current file has unsaved changes. Save before creating a new file?", "Unsaved Changes", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($result -eq "Yes") {
                Save-EditorFile
            }
            elseif ($result -eq "Cancel") {
                return
            }
        }
        $textBox.Clear()
        $global:RawrXD.CurrentFile = $null
        $global:RawrXD.Editor.CurrentFile = $null
        $global:RawrXD.Editor.IsModified = $false
        Update-EditorTitle
        Write-RawrXDLog "New file created" -Level SUCCESS -Component "TextEditor"
    }
}
function Open-EditorFile {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Title = "Open File"
    $openDialog.Filter = "All Files (*.*)|*.*|PowerShell Files (*.ps1)|*.ps1|Text Files (*.txt)|*.txt|Code Files (*.js;*.ts;*.py;*.cs)|*.js;*.ts;*.py;*.cs"
    $openDialog.FilterIndex = 1
    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Load-FileContent -FilePath $openDialog.FileName
    }
}
function Save-EditorFile {
    if ($global:RawrXD.CurrentFile) {
        Save-CurrentFile
    }
    else {
        Save-FileAs
    }
}
function Save-FileAs {
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = "Save File As"
    $saveDialog.Filter = "All Files (*.*)|*.*|PowerShell Files (*.ps1)|*.ps1|Text Files (*.txt)|*.txt"
    $saveDialog.FilterIndex = 1
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $global:RawrXD.CurrentFile = $saveDialog.FileName
        $global:RawrXD.Editor.CurrentFile = $saveDialog.FileName
        Save-CurrentFile
    }
}
function Save-CurrentFile {
    if ($global:RawrXD.CurrentFile -and $global:RawrXD.Components.TextEditor) {
        try {
            $content = $global:RawrXD.Components.TextEditor.Text
            [System.IO.File]::WriteAllText($global:RawrXD.CurrentFile, $content, [System.Text.Encoding]::UTF8)
            $global:RawrXD.Editor.IsModified = $false
            $global:RawrXD.Editor.LastSaveTime = Get-Date
            Update-EditorTitle
            Write-RawrXDLog "File saved: $($global:RawrXD.CurrentFile)" -Level SUCCESS -Component "TextEditor"
        }
        catch {
            Write-RawrXDLog "Failed to save file: $($_.Exception.Message)" -Level ERROR -Component "TextEditor"
            [System.Windows.Forms.MessageBox]::Show("Failed to save file:`n$($_.Exception.Message)", "Save Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}
function Load-FileContent {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) {
        [System.Windows.Forms.MessageBox]::Show("File not found: $FilePath", "File Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
    try {
        $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
        $global:RawrXD.Components.TextEditor.Text = $content
        $global:RawrXD.CurrentFile = $FilePath
        $global:RawrXD.Editor.CurrentFile = $FilePath
        $global:RawrXD.Editor.IsModified = $false
        Update-EditorTitle
        Apply-SyntaxHighlighting
        Write-RawrXDLog "File loaded: $FilePath" -Level SUCCESS -Component "TextEditor"
    }
    catch {
        Write-RawrXDLog "Failed to load file: $($_.Exception.Message)" -Level ERROR -Component "TextEditor"
        [System.Windows.Forms.MessageBox]::Show("Failed to load file:`n$($_.Exception.Message)", "Load Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}
function Apply-SyntaxHighlighting {
    $textBox = $global:RawrXD.Components.TextEditor
    if (-not $textBox -or -not $global:RawrXD.CurrentFile) { return }
    try {
        $language = Get-FileExtensionLanguage -FilePath $global:RawrXD.CurrentFile
        if ($language -eq "PowerShell") {
            Apply-PowerShellHighlighting -TextBox $textBox
        }
        elseif ($language -eq "JavaScript" -or $language -eq "TypeScript") {
            Apply-JavaScriptHighlighting -TextBox $textBox
        }
        # Add more language support as needed
    }
    catch {
        Write-RawrXDLog "Syntax highlighting error: $($_.Exception.Message)" -Level WARNING -Component "TextEditor"
    }
}
function Apply-PowerShellHighlighting {
    param($TextBox)
    # Save current selection
    $selStart = $TextBox.SelectionStart
    $selLength = $TextBox.SelectionLength
    # Clear formatting
    $TextBox.SelectAll()
    $TextBox.SelectionColor = $TextBox.ForeColor
    # Define PowerShell keywords and colors
    $keywords = @{
        'function|if|else|elseif|foreach|while|do|until|switch|case|default|try|catch|finally|param|begin|process|end|return|break|continue|throw' = [System.Drawing.Color]::Blue
        '\$\w+' = [System.Drawing.Color]::FromArgb(0, 128, 128)  # Variables
        '#.*$' = [System.Drawing.Color]::Green  # Comments
        '"[^"]*"' = [System.Drawing.Color]::Red  # Strings
        "'[^']*'" = [System.Drawing.Color]::Red  # Strings
    }
    $text = $TextBox.Text
    foreach ($pattern in $keywords.Keys) {
        $regex = [System.Text.RegularExpressions.Regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
        $matches = $regex.Matches($text)
        foreach ($match in $matches) {
            $TextBox.Select($match.Index, $match.Length)
            $TextBox.SelectionColor = $keywords[$pattern]
        }
    }
    # Restore selection
    $TextBox.Select($selStart, $selLength)
}
function Apply-JavaScriptHighlighting {
    param($TextBox)
    # Save current selection
    $selStart = $TextBox.SelectionStart
    $selLength = $TextBox.SelectionLength
    # Clear formatting
    $TextBox.SelectAll()
    $TextBox.SelectionColor = $TextBox.ForeColor
    # Define JavaScript keywords and colors
    $keywords = @{
        '\b(function|var|let|const|if|else|for|while|do|switch|case|default|try|catch|finally|return|break|continue|throw|class|extends|import|export|async|await)\b' = [System.Drawing.Color]::Blue
        '//.*$' = [System.Drawing.Color]::Green  # Single-line comments
        '/\*[\s\S]*?\*/' = [System.Drawing.Color]::Green  # Multi-line comments
        '"[^"]*"' = [System.Drawing.Color]::Red  # Strings
        "'[^']*'" = [System.Drawing.Color]::Red  # Strings
        '`[^`]*`' = [System.Drawing.Color]::Red  # Template literals
    }
    $text = $TextBox.Text
    foreach ($pattern in $keywords.Keys) {
        $regex = [System.Text.RegularExpressions.Regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
        $matches = $regex.Matches($text)
        foreach ($match in $matches) {
            $TextBox.Select($match.Index, $match.Length)
            $TextBox.SelectionColor = $keywords[$pattern]
        }
    }
    # Restore selection
    $TextBox.Select($selStart, $selLength)
}
function Update-EditorTitle {
    $form = $global:RawrXD.Form
    if ($form) {
        $title = "RawrXD v$($global:RawrXD.Version) - AI-Powered Editor"
        if ($global:RawrXD.CurrentFile) {
            $fileName = [System.IO.Path]::GetFileName($global:RawrXD.CurrentFile)
            $title += " - $fileName"
            if ($global:RawrXD.Editor.IsModified) {
                $title += " *"
            }
        }
        $form.Text = $title
    }
    # Update status bar
    if (Get-Command Update-StatusBar -ErrorAction SilentlyContinue) {
        Update-StatusBar
    }
}
function Update-CursorPosition {
    $textBox = $global:RawrXD.Components.TextEditor
    $positionLabel = $global:RawrXD.Components.PositionLabel
    if ($textBox -and $positionLabel) {
        $currentIndex = $textBox.SelectionStart
        $lines = $textBox.Lines
        $line = 1
        $column = 1
        $charCount = 0
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($charCount + $lines[$i].Length + 1 -gt $currentIndex) {
                $line = $i + 1
                $column = $currentIndex - $charCount + 1
                break
            }
            $charCount += $lines[$i].Length + 1  # +1 for newline
        }
        $positionLabel.Text = "Line: $line, Column: $column"
    }
}
# Placeholder functions for advanced features
function Undo-EditorAction {
    Write-RawrXDLog "Undo functionality not yet implemented" -Level WARNING -Component "TextEditor"
}
function Redo-EditorAction {
    Write-RawrXDLog "Redo functionality not yet implemented" -Level WARNING -Component "TextEditor"
}
function Show-EditorFindDialog {
    Write-RawrXDLog "Find dialog not yet implemented" -Level WARNING -Component "TextEditor"
}
function Toggle-WordWrap {
    $textBox = $global:RawrXD.Components.TextEditor
    $wrapBtn = $global:RawrXD.Components.EditorButtons.WordWrap
    if ($textBox -and $wrapBtn) {
        $textBox.WordWrap = $wrapBtn.Checked
        $global:RawrXD.Settings.Editor.WordWrap = $wrapBtn.Checked
        Write-RawrXDLog "Word wrap: $($wrapBtn.Checked)" -Level INFO -Component "TextEditor"
    }
}
function Set-EditorZoom {
    $zoomCombo = $global:RawrXD.Components.EditorButtons.Zoom
    $textBox = $global:RawrXD.Components.TextEditor
    if ($zoomCombo -and $textBox) {
        $zoomText = $zoomCombo.SelectedItem -replace '%', ''
        $zoomFactor = [int]$zoomText / 100.0
        $newSize = [int]($global:RawrXD.Settings.UI.FontSize * $zoomFactor)
        $textBox.Font = New-Object System.Drawing.Font($global:RawrXD.Settings.UI.FontFamily, $newSize)
        Write-RawrXDLog "Zoom set to: $($zoomCombo.SelectedItem)" -Level INFO -Component "TextEditor"
    }
}
function Handle-AutoIndent {
    param($Sender, $EventArgs)
    # This is a placeholder for auto-indentation logic
    # Implementation would analyze the current line and apply appropriate indentation
}
function Handle-TabKey {
    param($Sender, $EventArgs)
    $textBox = $Sender
    if ($global:RawrXD.Settings.Editor.ConvertTabsToSpaces) {
        $EventArgs.Handled = $true
        $spaces = " " * $global:RawrXD.Settings.Editor.TabSize
        $textBox.SelectedText = $spaces
    }
}
function Analyze-EditorFile {
    if ($global:RawrXD.CurrentFile -and $global:RawrXD.OllamaAvailable) {
        $content = $global:RawrXD.Components.TextEditor.Text
        $language = Get-FileExtensionLanguage -FilePath $global:RawrXD.CurrentFile
        $prompt = "Please analyze this $language code and provide insights about its structure, potential improvements, and any issues you notice:`n`n$content"
        # Switch to chat tab and send analysis request
        $global:RawrXD.Components.RightTabs.SelectedTab = $global:RawrXD.Components.ChatTab
        if (Get-Command Send-ChatMessage -ErrorAction SilentlyContinue) {
            Send-ChatMessage -Message $prompt -IsSystemGenerated $true
        }
        Write-RawrXDLog "File analysis requested" -Level INFO -Component "TextEditor"
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("No file open or AI service not available", "Analysis Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}
# Export functions
Export-ModuleMember -Function @(
    'Initialize-TextEditor',
    'New-EditorFile',
    'Open-EditorFile',
    'Save-EditorFile',
    'Load-FileContent',
    'Undo-EditorAction',
    'Redo-EditorAction',
    'Show-EditorFindDialog',
    'Analyze-EditorFile',
    'Apply-SyntaxHighlighting',
    'Update-EditorTitle',
    'Update-CursorPosition'
)
