cd F:\
Write-Host "=== GIT STATUS ==="
git status --short
Write-Host "=== GIT ADD ==="
git add -A
Write-Host "=== GIT COMMIT ==="
git commit -m "Batch 11: Decode Allocation Hardening for Qwen32 TPS Gate"
Write-Host "=== GIT PUSH ==="
git push
Write-Host "DONE"
