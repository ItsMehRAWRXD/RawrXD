# RawrZ API test via curl - run with server already running (node run-server-only.js)
$base = "http://127.0.0.1:3000"
$calc = "C:/Windows/System32/calc.exe"

Write-Host "1. Health check..." -ForegroundColor Cyan
curl -s "$base/api/health" | ConvertFrom-Json | Format-List

Write-Host "`n2. Encrypt calc.exe..." -ForegroundColor Cyan
$enc = curl -s -X POST -F "file=@$calc" -F "algorithm=aes-256-gcm" -F "password=TestPass123" "$base/api/encrypt-file"
$enc | ConvertFrom-Json | Format-List

Write-Host "`n3. Download encrypted file..." -ForegroundColor Cyan
$encName = (($enc | ConvertFrom-Json).encryptedName)
if ($encName) {
  $outPath = ".\security-data\calc.exe.enc.downloaded"
  curl -s -o $outPath "$base/api/files/download/$encName"
  if (Test-Path $outPath) { Write-Host "Downloaded: $((Get-Item $outPath).Length) bytes to $outPath" -ForegroundColor Green }
}

Write-Host "`n4. Red Killer scan..." -ForegroundColor Cyan
curl -s -X POST -H "Content-Type: application/json" -d '@test-red-killer.json' "$base/red-killer-scan" | ConvertFrom-Json | Format-List

Write-Host "`n5. Stub generate..." -ForegroundColor Cyan
$stub = curl -s -X POST -H "Content-Type: application/json" -d '@test-stub.json' "$base/stub-generate-encrypted"
($stub | ConvertFrom-Json).success; Write-Host "Stub length: $(($stub | ConvertFrom-Json).stub.Length) chars"

Write-Host "`n6. Payload create..." -ForegroundColor Cyan
curl -s -X POST -H "Content-Type: application/json" -d '@test-payload.json' "$base/payload-create" | ConvertFrom-Json | Select-Object type, platform, size, checksum | Format-List

Write-Host "Done." -ForegroundColor Green
