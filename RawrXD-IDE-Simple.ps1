Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "RawrXD IDE"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = 'CenterScreen'

$textBox = New-Object System.Windows.Forms.RichTextBox
$textBox.Dock = 'Fill'
$textBox.BackColor = [System.Drawing.Color]::Black
$textBox.ForeColor = [System.Drawing.Color]::White
$textBox.Font = New-Object System.Drawing.Font('Consolas', 12)
$textBox.Text = "RawrXD IDE - Ready"

$form.Controls.Add($textBox)

[System.Windows.Forms.Application]::EnableVisualStyles()
$form.ShowDialog()