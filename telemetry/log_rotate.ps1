# Sovereign Engine Log Rotation
# Run as scheduled task every hour

$LogPath = "D:\RawrXD\telemetry\logs\sovereign"
$RetentionHours = 48

Get-ChildItem $LogPath -Filter "*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddHours(-$RetentionHours)
} | Remove-Item -Force

# Compress logs older than 1 hour
Get-ChildItem $LogPath -Filter "*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddHours(-1) -and $_.Extension -eq ".log"
} | ForEach-Object {
    Compress-Archive -Path $_.FullName -DestinationPath "$($_.FullName).zip" -Force
    Remove-Item $_.FullName -Force
}
