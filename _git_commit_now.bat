@echo off
cd /d F:\
git add ~dev/CMakeLists.txt ~dev/rawrxd/src/screenpilot/rawrxd_screenpilot_agent_v2.cpp ~dev/rawrxd/include/screenpilot/rawrxd_screenpilot_agent_v2.h ~dev/rawrxd/include/screenpilot/screenpilot_tool_policy_v2.h ~dev/web/screenpilot_authority.js
git commit -m "Reconstruct top-level CMakeLists.txt + add rawrxd_screenpilot_e2e V2 static library"
git push origin main
echo COMMIT_DONE > f:\~dev\_git_commit_status.txt
