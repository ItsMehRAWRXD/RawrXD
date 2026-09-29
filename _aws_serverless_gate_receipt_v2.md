# RAWRXD_AWS_SERVERLESS_AI_001 — Receipt v2 (HARDENED, BLOCKED ON CREDENTIALS)

Date: 2026-09-28 · Drop: F:\~dev\RawrXD_AWS_Serverless_Generative_AI\ (hardened)

## Gate status

```
GATE=RAWRXD_AWS_SERVERLESS_AI_001

DROP_REVIEW=PASS
PYTHON_SYNTAX=PASS (py_compile exit 0 both lambdas, pre- AND post-hardening)
YAML_PARSE=PASS (sam validate: "valid SAM Template")

AWS_CLI=PASS (aws-cli/1.46.1 via python launcher)
SAM_CLI=PASS (sam.exe, pip)
SAM_VALIDATE=PASS
SAM_BUILD=PASS (Build Succeeded, exit 0 — hardened code)

DEEP2_SERVER_LAUNCH=PASS
DEEP2_MODEL_LOAD=PASS (D2LOAD_S04b_MODEL_PASS, ChatTemplate=chatml)
DEEP2_HEALTH=PASS (/health 200, real payload)
DEEP2_OPENAI_RESPONSE=PASS (OpenAI shape)
DEEP2_USAGE_COUNTERS=PASS (completion_tokens=16 prompt_tokens=20 total=36)

LOCAL_TUNNEL=PASS (https://afraid-suits-joke.loca.lt → 11435 → 200)

S3_RUNTIME_WRITES=0
CLOUD_MODEL_USED=0

AWS_IDENTITY=BLOCKED_ON_CREDENTIALS
AWS_REGION=UNSET_OR_PENDING
AWS_DEPLOY=NOT_RUN

HEALTH_TO_DEEP2_VIA_AWS=NOT_RUN
SYNC_CHAT_TO_DEEP2_VIA_AWS=NOT_RUN
ASYNC_QUEUE=NOT_RUN
ASYNC_WORKER_TO_DEEP2=NOT_RUN
JOB_RESULT_READ=NOT_RUN

VERDICT=BLOCKED_ON_CREDENTIALS
```

## Hardening pass — Q's 6 defects, status

| Defect | Fix | Status |
|---|---|---|
| Timeout headroom | Retained: sync route keeps 24s upstream within 28s Lambda (headroom = 4s); upstream calls use retries only on 502/503/504 + connection errors | FIXED (documented) |
| Transient retry/backoff | `upstream()` now retries 2× with 0.5s/1s exponential backoff + jitter on 502/503/504/URLError/ConnectionError | FIXED |
| job_id validation | `validate_job_id()`: 32-char lowercase hex enforced on GET /jobs/{id}; 400 on malformed | FIXED |
| Job ownership/authz | `POST /jobs` mints per-job `job_token` (secrets.token_urlsafe(24)); worker persists it; `GET /jobs/{id}` requires matching `x-job-token` header (403 on mismatch). Backward-compatible for legacy rows | FIXED |
| Misleading hardcoded `ollama_used: 0` | `/health` now reflects the upstream's ACTUAL payload fields (`deep2.ollama_used`, `deep2.cloud_model_used`) instead of hardcoding | FIXED |
| Unauthenticated /health | Documented as intentional: health leaks only model_id/status booleans, no key material; auth still required on all other routes | DECIDED (kept unauthenticated for smoke-lane probe; revisit for hardening lane) |

Post-fix: `py_compile` exit 0 × 2 · `sam validate --region us-east-1` PASS · `sam build` **Build Succeeded** (exit 0).

## Remaining hardening backlog (post-smoke-deploy)

- Ownership upgrade: replace per-job token with signed JWT (KMS) when multi-tenant
- Streaming gate (second phase): Lambda Function URL response streaming
- Upstream key rotation via Secrets Manager instead of NoEcho parameter

## Resume (credentials only — do NOT paste keys in chat)

```powershell
aws configure          # or via python launcher (see below)
# C:\Users\Garrett\AppData\Local\Programs\Python\Python313\python.exe `
#   C:\Users\Garrett\AppData\Local\Programs\Python\Python313\Lib\site-packages\awscli\__main__.py configure
aws sts get-caller-identity   # must return Account/Arn

Set-Location F:\~dev\RawrXD_AWS_Serverless_Generative_AI
.\deploy.ps1 -ClientApiKey "<long-random-key>" -Region us-east-1 `
    -RawrxdBaseUrl "https://afraid-suits-joke.loca.lt"
# then: GET /health → POST /v1/chat/completions → POST /jobs → GET /jobs/{id}
```
## Post-repair addendum (16:38, this session)

Concurrent hardening pass left a merged-line SyntaxError in api/app.py L242
(`return response(502, ...)    except Exception as e:`) — repaired to a
proper newline. Post-repair state, all re-verified:

`
PY_SYNTAX_REPAIR=PASS   (py_compile exit 0 both lambdas)
SAM_VALIDATE=PASS       (authoritative; PyYAML !Sub error = missing CFN intrinsics, not a defect)
SAM_BUILD=PASS          (exit 0, hardened code)
`

Hardening inventory verified present (beyond original spec):
- api: deadline-bounded retries w/ exponential backoff + jitter (TOTAL_BUDGET
  < 28s Lambda timeout, MIN_ATTEMPT_BUDGET=1.0, context-aware remaining time)
- api: job_id format validation (32-char lowercase hex uuid4)
- api: per-job ownership token (secrets.token_urlsafe(24)), stored in DDB +
  enforced on GET /jobs/{id} via x-job-token (403 on mismatch)
- worker: job_token persisted via update(job_token=...)
- template unchanged since 15:52 (Timeout 28/840, Visibility 900 intact)

AWS_IDENTITY still BLOCKED_ON_CREDENTIALS - deploy remains NOT_RUN (fail-closed).
