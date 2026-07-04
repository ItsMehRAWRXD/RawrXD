$Script:sourceDir = "C:\Users\Garre\Desktop\Desktop\RawrZApp"
$Script:backupDir = "$sourceDir\sources-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

Write-Host "Creating comprehensive source backup..." -ForegroundColor Green
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

$Script:fileTypes = @{
    "JavaScript" = "*.js"
    "JSON" = "*.json"
    "HTML" = "*.html"
    "CSS" = "*.css"
    "C/C++" = @("*.c", "*.cpp", "*.h")
    "Assembly" = "*.asm"
    "PowerShell" = "*.ps1"
    "Shell" = "*.sh"
    "Python" = "*.py"
    "Docker" = "Dockerfile*"
    "YAML" = @("*.yml", "*.yaml")
    "Markdown" = "*.md"
}

foreach ($type in $fileTypes.Keys) {
$Script:typeDir = "$backupDir\$type"
    New-Item -ItemType Directory -Path $typeDir -Force | Out-Null
    
$Script:patterns = $fileTypes[$type]
    if ($patterns -is [array]) {
        foreach ($pattern in $patterns) {
            Get-ChildItem -Path $sourceDir -Filter $pattern -Recurse | 
                Copy-Item -Destination $typeDir -Force
        }
    } else {
        Get-ChildItem -Path $sourceDir -Filter $patterns -Recurse | 
            Copy-Item -Destination $typeDir -Force
    }
    
$Script:count = (Get-ChildItem -Path $typeDir).Count
    Write-Host "Saved $count $type files" -ForegroundColor Cyan
}

$Script:zipPath = "$sourceDir\rawrz-complete-sources-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
Compress-Archive -Path "$backupDir\*" -DestinationPath $zipPath -Force

Write-Host "Complete source backup created:" -ForegroundColor Green
Write-Host $zipPath -ForegroundColor Yellow
Write-Host "Backup directory: $backupDir" -ForegroundColor Yellow