cd F:\
Write-Host "=== GIT STATUS ==="
git status --short | Out-File -FilePath "F:\~dev\git_status_shell.txt" -Encoding utf8
Write-Host "=== GIT ADD ==="
git add ide_chatbot.html ~dev/index.html ~dev/serve_shell.js
Write-Host "=== GIT COMMIT ==="
git commit -m "screenpilot: complete tiered shell UX and browser validation" -m "SCREENPILOT_SHELL_UX_001=PASS" -m "SHELL_BROWSER_AUTHORITY=PASS" -m "PUBLIC_PRODUCT_COHERENCE_READY=1" | Out-File -FilePath "F:\~dev\git_commit_shell.txt" -Encoding utf8
Write-Host "=== GIT LOG ==="
git log --oneline -1 | Out-File -FilePath "F:\~dev\git_log_shell.txt" -Encoding utf8
Write-Host "DONE"
