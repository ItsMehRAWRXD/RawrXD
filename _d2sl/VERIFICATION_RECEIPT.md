# Verification Receipt — Deep2 Serverless AI

Date: 2026-09-28

## Build verification

Command:

```bash
cmake -S . -B build-linux
cmake --build build-linux -- -j2
```

Observed:

```text
[ 50%] Building CXX object CMakeFiles/deep2-serverless.dir/deep2_serverless.cpp.o
[100%] Linking CXX executable deep2-serverless
[100%] Built target deep2-serverless
```

Compiler flags used by the project on the verification host:

```text
-std=c++20 -Wall -Wextra -Wpedantic
```

Result:

```text
PORTABLE_CXX20_BUILD=PASS
COMPILER_WARNINGS=0
```

## Control-plane smoke test

A disposable HTTP process was used only as a deterministic upstream transport
fixture. It did **not** simulate or certify Deep2 inference.

Verified:

```text
SERVER_READY=PASS
GET_HEALTH=PASS
SYNC_CHAT_PROXY=PASS
ASYNC_JOB_SUBMIT=PASS
ASYNC_JOB_WORKER=PASS
ASYNC_JOB_RESULT=PASS
DURABLE_REQUEST_FILE=PASS
DURABLE_STATUS_FILE=PASS
DURABLE_RESULT_FILE=PASS
```

Observed gateway health:

```json
{
  "serverless_gateway": "ok",
  "deep2_upstream_reachable": true,
  "deep2_upstream_status": 200,
  "ollama_used": 0,
  "cloud_model_used": 0
}
```

Observed asynchronous transition:

```text
queued -> running -> completed
```

Durable files observed:

```text
jobs/<job-id>/request.json
jobs/<job-id>/result.json
jobs/<job-id>/result.meta
jobs/<job-id>/status.txt
```

## Restart recovery test

A durable job was placed in `queued` state before gateway startup.

At startup the gateway reloaded the job, queued it, dispatched it to a worker,
persisted the result, and returned:

```json
{
  "job_id": "recovery-job",
  "status": "completed",
  "upstream_http_status": 200,
  "result": {
    "choices": [
      {
        "message": {
          "role": "assistant",
          "content": "RECOVERY_OK"
        }
      }
    ]
  }
}
```

Result:

```text
JOB_RESTART_RECOVERY=PASS
```

## Not claimed by this receipt

This verification environment does not contain the user's Windows RawrXD
workspace, GGUF files, GPU stack, or running `deep2_openai_server.exe`.

Therefore these must still be certified on the target machine:

```text
WINDOWS_MSVC_BUILD
REAL_DEEP2_UPSTREAM
REAL_GGUF_MODEL_LOAD
REAL_FORWARD_PASS
REAL_GENERATED_TOKENS
REAL_GPU_PATH
```

Do not mark the final production gate PASS until those target-machine checks
succeed.

## Target-machine final gate

```text
GATE=DEEP2_SERVERLESS_AI_001

SOURCE_ONLY=1
THIRD_PARTY_DEPS=0

WINDOWS_MSVC_BUILD=PASS
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

REAL_MODEL_LOAD=PASS
REAL_GENERATED_TOKEN_COUNT_GT_0=PASS

OLLAMA_USED=0
CLOUD_MODEL_USED=0

VERDICT=PASS
```
