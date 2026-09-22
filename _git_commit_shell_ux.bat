@echo off
cd /d F:\
git add ide_chatbot.html ~dev/index.html ~dev/serve_shell.js
git status --short > f:\~dev\git_status_shell_ux.txt 2>&1
git commit -m "screenpilot: complete tiered shell UX and browser validation" -m "SCREENPILOT_SHELL_UX_001=PASS" -m "SHELL_BROWSER_AUTHORITY=PASS" -m "PUBLIC_PRODUCT_COHERENCE_READY=1" -m "" -m "- HTTP shell load PASS" -m "- DEFAULT / ADVANCED / LABS navigation PASS" -m "- 33 nav items rendered" -m "- Ollama Direct backend connection PASS" -m "- model selector population PASS" -m "- real chat inference PASS" -m "- latency/token telemetry PASS" -m "- zero browser console errors" -m "- static regression PASS"
git log --oneline -1 > f:\~dev\git_commit_shell_ux.txt 2>&1
echo done > f:\~dev\_git_done_shell_ux.txt
