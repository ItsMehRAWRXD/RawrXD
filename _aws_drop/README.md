# RawrXD AWS Serverless Generative AI

AWS is the serverless **control plane**. RawrXD/Deep2 remains the only
generative inference backend.

## Why this matches the August cost signal

The July -> August S3 increase was almost entirely Tier-1 request activity.
This design does not use S3 for chat messages, token chunks, or job results.

Runtime:
- API Gateway HTTP API
- Lambda
- SQS for long jobs
- DynamoDB PAY_PER_REQUEST for job status/results
- CloudWatch logs
- RawrXD/Deep2 for inference

`sam deploy --resolve-s3` performs a few deployment-time S3 artifact uploads;
S3 is not in the runtime path.

## Routes

- `GET /health`
- `POST /v1/chat/completions`
- `POST /jobs`
- `GET /jobs/{id}`

Protected routes require:

```text
x-rawrxd-key: <ClientApiKey>
```

The synchronous chat endpoint forces `stream=false` and clamps output tokens
to avoid turning a short API request into a long-running local inference job.
Use `/jobs` for longer generations.

## Deploy

Prerequisites:
- AWS CLI authenticated
- AWS SAM CLI

```powershell
cd <drop-folder>

.\deploy.ps1 `
  -ClientApiKey "replace-with-a-long-random-key" `
  -Region us-east-1 `
  -RawrxdBaseUrl "https://smart-otters-follow.loca.lt"
```

The stack outputs `ApiUrl`.

## Test health

```powershell
$Api = "https://YOUR_ID.execute-api.us-east-1.amazonaws.com"

Invoke-RestMethod `
  -Uri "$Api/health" `
  -Method Get
```

Expected shape:

```json
{
  "serverless_gateway": "ok",
  "deep2_upstream_status": 200,
  "ollama_used": 0
}
```

## Test synchronous Deep2 generation

```powershell
$Api = "https://YOUR_ID.execute-api.us-east-1.amazonaws.com"
$Key = "replace-with-a-long-random-key"

$body = @{
  model = "qwen2.5-coder-1.5b-base"
  messages = @(
    @{
      role = "user"
      content = "Reply with exactly: DEEP2_SERVERLESS_OK"
    }
  )
  max_tokens = 32
  stream = $false
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Uri "$Api/v1/chat/completions" `
  -Method Post `
  -Headers @{ "x-rawrxd-key" = $Key } `
  -ContentType "application/json" `
  -Body $body
```

## Test asynchronous generation

```powershell
$job = Invoke-RestMethod `
  -Uri "$Api/jobs" `
  -Method Post `
  -Headers @{ "x-rawrxd-key" = $Key } `
  -ContentType "application/json" `
  -Body $body

$job

Invoke-RestMethod `
  -Uri "$Api/jobs/$($job.job_id)" `
  -Method Get `
  -Headers @{ "x-rawrxd-key" = $Key }
```

Statuses:
- `queued`
- `running`
- `completed`
- `failed`

Completed job records expire automatically using DynamoDB TTL.

## Current tunnel boundary

`https://smart-otters-follow.loca.lt` is suitable for proving the path but
should not be treated as a permanent production origin. Replace it with a
stable authenticated HTTPS ingress before broad external use.

## Streaming

This drop intentionally uses a buffered HTTP API for the synchronous path.
AWS currently supports Lambda/API response streaming, but enabling that should
be a separate certification gate after this simpler Deep2 path is proven.
The `/jobs` route handles long work without keeping a client connection open.

## Acceptance gate

```text
GATE=RAWRXD_AWS_SERVERLESS_AI_001

HTTP_API_DEPLOY=PASS
HEALTH_TO_DEEP2=PASS
SYNC_CHAT_TO_DEEP2=PASS
ASYNC_QUEUE=PASS
ASYNC_WORKER_TO_DEEP2=PASS
JOB_RESULT_READ=PASS
S3_RUNTIME_WRITES=0
OLLAMA_USED=0
CLOUD_MODEL_USED=0

VERDICT=PASS
```
