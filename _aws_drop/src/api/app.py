import base64, json, os, time, urllib.error, urllib.request, uuid
import boto3

BASE = os.environ["RAWXD_BASE_URL"].rstrip("/")
UPSTREAM_KEY = os.environ.get("RAWXD_UPSTREAM_KEY", "rawrxd")
CLIENT_KEY = os.environ["CLIENT_API_KEY"]
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
QUEUE = os.environ["JOB_QUEUE_URL"]
TABLE = os.environ["JOBS_TABLE"]
MAX_SYNC_TOKENS = int(os.environ.get("MAX_SYNC_TOKENS", "128"))

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

def upstream(path, method="GET", payload=None, timeout=20):
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
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(6 * 1024 * 1024)
            return r.status, json.loads(raw.decode())
    except urllib.error.HTTPError as e:
        raw = e.read(512 * 1024)
        try:
            detail = json.loads(raw.decode())
        except Exception:
            detail = {"error": raw.decode(errors="replace")}
        return e.code, detail

def route(event):
    http = (event.get("requestContext") or {}).get("http") or {}
    return http.get("method", "").upper(), event.get("rawPath") or http.get("path") or "/"

def handler(event, context):
    try:
        method, path = route(event)

        if method == "GET" and path == "/health":
            code, detail = upstream("/health", timeout=5)
            return response(200 if code == 200 else 503, {
                "serverless_gateway": "ok",
                "deep2_upstream_status": code,
                "deep2": detail,
                "ollama_used": 0,
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
            code, detail = upstream("/v1/chat/completions", "POST", req, 24)
            return response(code, detail)

        if method == "POST" and path == "/jobs":
            raw = body(event)
            req = raw.get("request", raw)
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
            req["stream"] = False
            job_id = str(uuid.uuid4())
            message = json.dumps({
                "job_id": job_id,
                "submitted_at": int(time.time()),
                "request": req,
            }, separators=(",", ":"))
            if len(message.encode()) > 240 * 1024:
                raise ValueError("job payload too large")
            sqs.send_message(QueueUrl=QUEUE, MessageBody=message)
            return response(202, {
                "job_id": job_id,
                "status": "queued",
                "status_url": f"/jobs/{job_id}",
            })

        if method == "GET" and path.startswith("/jobs/"):
            job_id = path.split("/", 2)[2]
            item = ddb.get_item(
                TableName=TABLE,
                Key={"job_id": {"S": job_id}},
            ).get("Item")
            if not item:
                return response(404, {"error": "job not found"})
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
