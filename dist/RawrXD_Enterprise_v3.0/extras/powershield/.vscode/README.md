# VSCode Workspace Configuration

This folder contains VSCode workspace settings for the Powershield project.

## Files

- **settings.json** - Workspace-specific editor and language settings
- **extensions.json** - Recommended extensions for this project
- **tasks.json** - Common build and test tasks
- **launch.json** - Debug configurations for PowerShell scripts

## Recommended Extensions

After opening this workspace, VSCode will prompt you to install recommended extensions. The most important one is:

- **PowerShell** (`ms-vscode.powershell`) - Required for PowerShell syntax highlighting, IntelliSense, and debugging

## Quick Start

1. Install recommended extensions when prompted
2. Open any `.ps1` file to start editing
3. Press `F5` to debug the current PowerShell script
4. Press `Ctrl+Shift+B` to run build tasks
5. Press `Ctrl+Shift+P` and type "PowerShell: Select PowerShell Version" to choose your PowerShell version

## Troubleshooting

If PowerShell extension isn't working:

1. Open Command Palette (`Ctrl+Shift+P`)
2. Run "PowerShell: Show Extension Logs"
3. Check for errors in the Output panel

If IntelliSense isn't working:

1. Ensure PowerShell extension is installed and enabled
2. Check that PowerShell is in your PATH
3. Restart VSCode

