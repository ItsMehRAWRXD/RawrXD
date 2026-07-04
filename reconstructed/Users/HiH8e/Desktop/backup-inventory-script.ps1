$Script:src = 'C:\Users\HiH8e\Desktop\inventory-ollama-and-folders.ps1'
$Script:dst = 'C:\Users\HiH8e\Desktop\inventory-ollama-and-folders.ps1.backup'
$Script:content = Get-Content -Raw -Path $src
Set-Content -Path $dst -Value $content
Write-Output "BACKUP_CREATED:$dst"