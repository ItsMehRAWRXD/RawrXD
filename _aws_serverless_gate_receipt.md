# RAWRXD_AWS_SERVERLESS_AI_001 — Deploy-Ready Evidence (BLOCKED ON CREDENTIALS)

Date: 2026-09-28 · Drop: F:\~dev\RawrXD_AWS_Serverless_Generative_AI\ (6 files, audited)

## Deploy-prerequisite evidence (all verified live this session)

| Prerequisite | Status | Evidence |
|---|---|---|
| Source drop complete | PASS | template.yaml (3776B) · deploy.ps1 (976B) · README.md · src/api/app.py (5679B) · src/worker/app.py (2872B) · .gitignore |
| Drop code audit | PASS | HttpApi + 4 routes + ApiFunction(SQS/DDB grants) + Worker(SQS event, ReportBatchItemFailures) + DLQ + TTL table; upstream Bearer + tunnel-reminder header present; sync route forces stream=false and clamps tokens |
| Deep2 upstream (local) | PASS | rawr-server.exe --model F:\~dev\qwen2.5-coder-1.5b-base.gguf --port 11435 → /health 200 {"model_id":"qwen2.5-coder-1.5b-base","model_loaded":true,"status":"ok"}; stderr shows D2LOAD_S04b_MODEL_PASS, ChatTemplate=chatml, "[server] Ready." |
| Upstream chat contract | PASS | POST /v1/chat/completions → 200 OpenAI shape {"choices":[...],"usage":{"completion_tokens":16,"prompt_tokens":20,"total_tokens":36}} (Deep2 real inference, OLLAMA_CALLS=0) |
| Public tunnel | PASS | https://afraid-suits-joke.loca.lt → 11435: /health 200 with bypass-tunnel-reminder header |
| SAM CLI | PASS | C:\Users\...\Python313\Scripts\sam.exe (pip install aws-sam-cli, exit 0) |
| AWS CLI | PASS | aws-cli/1.46.1 (pip); run via python.exe ...site-packages\awscli\__main__.py (host .py association broken) |
| AWS credentials | **MISSING** | `aws sts get-caller-identity` → "Unable to locate credentials"; ~/.aws has only SSO/AmazonQ caches (no account/role binding; SSO portal listAccounts → 401 with cached token) |

## Interference absorbed this session

- rawr-server.exe found dead (old instance died); restarted with correct `--model <path>` args (first restart used a model-id and died).
- loca.lt subdomain changed twice (tunnel died with old server): now afraid-suits-joke.loca.lt.
- winget AWS CLI blocked by system MSI mutex (msiexec 1618, PID 24812 kill denied) — bypassed via pip.

## Gate receipt (fail-closed)

```
GATE=RAWRXD_AWS_SERVERLESS_AI_001
DROP_COMPLETE=1
UPSTREAM_HEALTH_TO_DEEP2=PASS (local 200 + tunnel 200)
UPSTREAM_CHAT_TO_DEEP2=PASS (200, OpenAI shape, OLLAMA_USED=0, CLOUD_MODEL_USED=0)
SAM_TOOLCHAIN=PASS
AWS_CREDENTIALS=MISSING
HTTP_API_DEPLOY=NOT_RUN (blocked on credentials)
SYNC_CHAT_TO_DEEP2=NOT_RUN
ASYNC_QUEUE=NOT_RUN
JOB_RESULT_READ=NOT_RUN
S3_RUNTIME_WRITES=0 (by design)
VERDICT=BLOCKED_ON_CREDENTIALS
```

## Resume (when credentials available)

```powershell
# 1. Authenticate (either):
aws configure   # access key + secret + us-east-1
# or via the fixed launcher:
# C:\Users\Garrett\AppData\Local\Programs\Python\Python313\python.exe `
#   C:\Users\Garrett\AppData\Local\Programs\Python\Python313\Lib\site-packages\awscli\__main__.py configure

# 2. Deploy (tunnel URL is the CURRENT live one):
Set-Location F:\~dev\RawrXD_AWS_Serverless_Generative_AI
.\deploy.ps1 -ClientApiKey "<long-random-key>" -Region us-east-1 `
    -RawrxdBaseUrl "https://afraid-suits-joke.loca.lt"

# 3. Test: (Api/Key from outputs)
Invoke-RestMethod "$Api/health"
Invoke-RestMethod -Uri "$Api/v1/chat/completions" -Method Post `
    -Headers @{ "x-rawrxd-key" = $Key } -ContentType "application/json" `
    -Body ($body | ConvertTo-Json -Depth 10)
```

NOTE: keep tunnel + rawr-server alive during tests; if the tunnel URL changes,
re-deploy with the new `-RawrxdBaseUrl`.