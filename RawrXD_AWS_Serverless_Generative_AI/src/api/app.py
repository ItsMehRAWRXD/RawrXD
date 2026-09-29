import base64, json, os, secrets, time, urllib.error, urllib.request, uuid
import boto3

BASE = os.environ["RAWXD_BASE_URL"].rstrip("/")
UPSTREAM_KEY = os.environ.get("RAWXD_UPSTREAM_KEY", "rawrxd")
CLIENT_KEY = os.environ["CLIENT_API_KEY"]
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
QUEUE = os.environ["JOB_QUEUE_URL"]
TABLE = os.environ["JOBS_TABLE"]
MAX_SYNC_TOKENS = int(os.environ.get("MAX_SYNC_TOKENS", "128"))

# Deadline budget for the whole request (retries included). Kept below the
# Lambda's 28s timeout so the handler always gets to write its own response.
TOTAL_BUDGET = float(os.environ.get("SYNC_TOTAL_BUDGET", "26"))
SAFETY_MARGIN = float(os.environ.get("SYNC_SAFETY_MARGIN", "2"))
MIN_ATTEMPT_BUDGET = 1.0  # never start an attempt with less than this left

sqs = boto3.client("sqs")
ddb = boto3.client("dynamodb")

def response(status, payload):
    return {
        "statusCode": status,
        "headers": {
            "content-type": "application/json",
            "access-control-allow-origin": ORIGIN,
            "cache-control": "no-store",
        },
        "body": json.dumps(payload, separators=(",", ":")),
    }

def body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    if len(raw.encode("utf-8")) > 128 * 1024:
        raise ValueError("request exceeds 128 KiB")
    return json.loads(raw) if raw else {}

def headers(event):
    return {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}

def authorized(event):
    return headers(event).get("x-rawrxd-key", "") == CLIENT_KEY

def lambda_remaining(context):
    """Remaining invocation time in seconds, from the Lambda context when
    available; falls back to the local wall-clock budget."""
    fn = getattr(context, "get_remaining_time_in_millis", None)
    if callable(fn):
        try:
            return fn() / 1000.0
        except Exception:
            pass
    return TOTAL_BUDGET


def upstream(path, method="GET", payload=None, timeout=20, retries=2, context=None):
    """Deadline-bounded upstream call.

    Every attempt's timeout is clamped to the remaining invoke budget, backoff
    only runs when there is budget left, and retrying stops once an attempt
    could not finish before the deadline. This makes the retry system genuinely
    bounded rather than best-effort.
    """
    import random
    deadline = time.monotonic() + min(TOTAL_BUDGET, lambda_remaining(context)) - SAFETY_MARGIN
    last_error = None
    for attempt in range(retries + 1):
        remaining = deadline - time.monotonic()
        if remaining <= MIN_ATTEMPT_BUDGET:
            # Out of budget: return a controlled timeout rather than risk
            # Lambda killing the handler mid-flight.
            return 504, {"error": "upstream deadline exceeded before attempt",
                         "attempts": attempt}
        if attempt:
            backoff = 0.5 * (2 ** (attempt - 1)) + random.random() * 0.1
            if deadline - time.monotonic() - backoff <= MIN_ATTEMPT_BUDGET:
                return 504, {"error": "upstream deadline exceeded before backoff",
                             "attempts": attempt}
            time.sleep(backoff)
        attempt_timeout = max(MIN_ATTEMPT_BUDGET,
                              min(timeout, deadline - time.monotonic()))
        try:
            return _upstream_once(path, method, payload, attempt_timeout)
        except urllib.error.HTTPError as e:
            raw = e.read(512 * 1024)
            try:
                detail = json.loads(raw.decode())
            except Exception:
                detail = {"error": raw.decode(errors="replace")}
            if e.code in (502, 503, 504) and attempt < retries:
                last_error = e
                continue
            return e.code, detail
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last_error = e
            if attempt < retries:
                continue
            return 504, {"error": f"upstream unreachable: {type(e).__name__}"}
    if isinstance(last_error, urllib.error.HTTPError):
        return last_error.code, {"error": "upstream error after retries"}
    return 504, {"error": "upstream retries exhausted"}

def _upstream_once(path, method="GET", payload=None, timeout=20):
    data = None
    h = {
        "accept": "application/json",
        "authorization": f"Bearer {UPSTREAM_KEY}",
        "bypass-tunnel-reminder": "true",
    }
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        h["content-type"] = "application/json"

    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(6 * 1024 * 1024)
        return r.status, json.loads(raw.decode())

def validate_job_id(job_id):
    """job_id must be a 32-char lowercase hex uuid4 — blocks traversal/injection."""
    return (
        isinstance(job_id, str)
        and len(job_id) == 32
        and all(c in "0123456789abcdef" for c in job_id.lower())
    )

def make_job_token():
    """Per-job bearer for /jobs/{id} reads (weak ownership proof for smoke lane)."""
    return secrets.token_urlsafe(24)

def route(event):
    http = (event.get("requestContext") or {}).get("http") or {}
    return http.get("method", "").upper(), event.get("rawPath") or http.get("path") or "/"

def handler(event, context):
    try:
        method, path = route(event)

        if method == "GET" and path == "/health":
            code, detail = upstream("/health", timeout=8, context=context)
            # Reflect the REAL upstream payload fields; do not hardcode claims
            # the upstream did not actually make.
            deep2 = detail if isinstance(detail, dict) else {}
            return response(200 if code == 200 else 503, {
                "serverless_gateway": "ok",
                "deep2_upstream_status": code,
                "deep2": deep2,
                "ollama_used": deep2.get("ollama_used"),
                "cloud_model_used": deep2.get("cloud_model_used"),
            })

        if not authorized(event):
            return response(401, {"error": "unauthorized"})

        if method == "POST" and path == "/v1/chat/completions":
            req = body(event)
            if not isinstance(req, dict):
                raise ValueError("JSON body must be an object")
            if req.get("stream"):
                return response(400, {"error": {
                    "message": "Buffered route: set stream=false or use POST /jobs."
                }})
            req["stream"] = False
            try:
                n = int(req.get("max_tokens", MAX_SYNC_TOKENS))
            except Exception:
                n = MAX_SYNC_TOKENS
            req["max_tokens"] = max(1, min(n, MAX_SYNC_TOKENS))
            code, detail = upstream("/v1/chat/completions", "POST", req, 24,
                                    context=context)
            return response(code, detail)

        if method == "POST" and path == "/jobs":
            raw = body(event)
            req = raw.get("request", raw)
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
            req["stream"] = False
            job_id = str(uuid.uuid4())
            job_token = secrets.token_urlsafe(24)
            message = json.dumps({
                "job_id": job_id,
                "job_token": job_token,
                "submitted_at": int(time.time()),
                "request": req,
            }, separators=(",", ":"))
            if len(message.encode()) > 240 * 1024:
                raise ValueError("job payload too large")
            # Create the job row up-front so ownership is enforceable from the
            # very first read (status=queued) instead of only after the worker
            # picks the message up.
            ddb.put_item(
                TableName=TABLE,
                Item={
                    "job_id": {"S": job_id},
                    "job_token": {"S": job_token},
                    "status": {"S": "queued"},
                    "updated_at": {"N": str(int(time.time()))},
                },
            )
            sqs.send_message(QueueUrl=QUEUE, MessageBody=message)
            return response(202, {
                "job_id": job_id,
                "job_token": job_token,
                "status": "queued",
                "status_url": f"/jobs/{job_id}",
            })

        if method == "GET" and path.startswith("/jobs/"):
            job_id = path.split("/", 2)[2]
            if not validate_job_id(job_id):
                return response(400, {"error": "malformed job_id"})
            item = ddb.get_item(
                TableName=TABLE,
                Key={"job_id": {"S": job_id}},
            ).get("Item")
            if not item:
                return response(404, {"error": "job not found"})
            # Ownership: caller must present the job_token issued at submit.
            supplied = headers(event).get("x-job-token", "")
            stored = item.get("job_token", {}).get("S", "")
            if stored and supplied != stored:
                return response(403, {"error": "job token mismatch"})
            out = {
                "job_id": job_id,
                "status": item.get("status", {}).get("S", "unknown"),
                "updated_at": int(item.get("updated_at", {}).get("N", "0")),
            }
            if "result_json" in item:
                out["result"] = json.loads(item["result_json"]["S"])
            if "error" in item:
                out["error"] = item["error"]["S"]
            return response(200, out)

        return response(404, {"error": "route not found"})

    except ValueError as e:
        return response(400, {"error": str(e)})
    except urllib.error.URLError as e:
        return response(502, {"error": f"Deep2 upstream unavailable: {e}"})
    except Exception as e:
        print(json.dumps({
            "level": "error",
            "request_id": getattr(context, "aws_request_id", ""),
            "error": str(e),
        }))
        return response(500, {"error": "internal gateway error"})
