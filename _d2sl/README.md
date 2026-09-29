# Deep2 Serverless AI

A source-only C++20 local control plane that gives Deep2 the same operational
shape as the AWS serverless package without AWS, Ollama, or cloud inference.

## Runtime shape

```text
Client / IDE / agent
        |
        v
deep2-serverless :11437
        |
        +-- POST /v1/chat/completions  -> synchronous Deep2 call
        |
        +-- POST /jobs                 -> durable local queue
        |                                 |
        |                                 v
        |                           worker threads
        |                                 |
        +---------------------------------+
                                          |
                                          v
                               deep2_openai_server :11436
                                          |
                                          v
                                      Deep2Engine
                                          |
                                          v
                                      local GGUF
```

This does not replace Deep2 inference. It makes the existing Deep2
OpenAI-compatible server behave like a local serverless inference service.

## No dependencies

- C++20
- Windows: Winsock2 only (`ws2_32`)
- Linux: POSIX sockets + pthreads
- no Boost
- no curl
- no JSON library
- no database
- no AWS SDK
- no Ollama

The OpenAI request body is passed byte-for-byte to Deep2.

## Routes

### `GET /health`

Checks whether the local Deep2 upstream responds.

### `POST /v1/chat/completions`

Passes the request directly to:

```text
127.0.0.1:11436/v1/chat/completions
```

The gateway is buffered. Use `"stream": false`.

### `POST /jobs`

Persists the OpenAI request before acknowledging it and queues it for a worker.

Returns:

```json
{
  "job_id": "...",
  "status": "queued",
  "status_url": "/jobs/..."
}
```

### `GET /jobs/{id}`

Returns one of:

```text
queued
running
completed
failed
```

A completed result includes the real Deep2 JSON response.

## Durable job state

Jobs live under:

```text
.deep2_serverless/
└── jobs/
    └── <job-id>/
        ├── request.json
        ├── status.txt
        ├── result.meta
        ├── result.json
        └── error.txt
```

Requests are persisted before they enter the in-memory queue.

If the gateway restarts, jobs left in `queued` or `running` state are loaded
back into the queue automatically.

Writes use temporary files and rename for crash-resistant state transitions.

## Windows build

```powershell
.\build.ps1
```

Equivalent manual build:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Start Deep2

Run your existing Deep2 OpenAI-compatible server on port 11436.

Example environment:

```powershell
$env:DEEP2_SERVER_PORT = "11436"
```

Then start the local serverless control plane:

```powershell
.\run.ps1
```

Defaults:

```text
Deep2 upstream = 127.0.0.1:11436
Gateway        = 127.0.0.1:11437
Workers        = 2
```

## Optional API key

```powershell
.\run.ps1 -ApiKey "replace-with-a-long-local-key"
```

Then send:

```text
x-deep2-key: replace-with-a-long-local-key
```

`/health` remains available without the key.

## PowerShell test

```powershell
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
    -Uri "http://127.0.0.1:11437/v1/chat/completions" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

## Long generation

```powershell
$job = Invoke-RestMethod `
    -Uri "http://127.0.0.1:11437/jobs" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body

$job

Invoke-RestMethod `
    -Uri "http://127.0.0.1:11437/jobs/$($job.job_id)" `
    -Method Get
```

## Configuration

Environment variables:

```text
DEEP2_SERVERLESS_HOST       default 127.0.0.1
DEEP2_SERVERLESS_PORT       default 11437
DEEP2_UPSTREAM_HOST         default 127.0.0.1
DEEP2_UPSTREAM_PORT         default 11436
DEEP2_SERVERLESS_API_KEY    default empty/local-only
DEEP2_SERVERLESS_STATE      default .deep2_serverless
DEEP2_SERVERLESS_WORKERS    default 2
DEEP2_UPSTREAM_TIMEOUT      default 780 seconds
```

## Intended certification

```text
GATE=DEEP2_SERVERLESS_AI_001

SOURCE_ONLY=1
THIRD_PARTY_DEPS=0

SERVER_READY=PASS
DEEP2_UPSTREAM_REACHABLE=PASS

SYNC_CHAT_ACCEPTED=PASS
SYNC_DEEP2_HTTP_200=PASS
SYNC_RESULT_RETURNED=PASS

JOB_PERSIST_BEFORE_ACK=PASS
JOB_QUEUE=PASS
JOB_WORKER=PASS
JOB_RESULT_DURABLE=PASS
JOB_RESTART_RECOVERY=PASS

OLLAMA_USED=0
CLOUD_MODEL_USED=0

VERDICT=PASS
```

`VERDICT=PASS` should only be emitted after running this against the actual
Deep2 server and a real local model. A standalone control-plane smoke test does
not prove Deep2 inference.
