import json, os, time, urllib.error, urllib.request
import boto3

BASE = os.environ["RAWXD_BASE_URL"].rstrip("/")
UPSTREAM_KEY = os.environ.get("RAWXD_UPSTREAM_KEY", "rawrxd")
TABLE = os.environ["JOBS_TABLE"]
TTL_DAYS = int(os.environ.get("JOB_TTL_DAYS", "7"))
ddb = boto3.client("dynamodb")

def update(job_id, status, result=None, error=None):
    now = int(time.time())
    values = {
        ":s": {"S": status},
        ":u": {"N": str(now)},
        ":e": {"N": str(now + TTL_DAYS * 86400)},
    }
    expr = "SET #s=:s, updated_at=:u, expires_at=:e"
    names = {"#s": "status"}
    if result is not None:
        values[":r"] = {"S": json.dumps(result, separators=(",", ":"))[:350000]}
        expr += ", result_json=:r"
    if error is not None:
        values[":x"] = {"S": str(error)[:16000]}
        expr += ", error=:x"
    ddb.update_item(
        TableName=TABLE,
        Key={"job_id": {"S": job_id}},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

def call_deep2(payload):
    payload = dict(payload)
    payload["stream"] = False
    req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {UPSTREAM_KEY}",
            "bypass-tunnel-reminder": "true",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=780) as r:
            raw = r.read(6 * 1024 * 1024)
            return r.status, json.loads(raw.decode())
    except urllib.error.HTTPError as e:
        raw = e.read(512 * 1024)
        try:
            detail = json.loads(raw.decode())
        except Exception:
            detail = {"error": raw.decode(errors="replace")}
        return e.code, detail

def handler(event, context):
    failures = []
    for record in event.get("Records", []):
        msg_id = record.get("messageId", "")
        try:
            env = json.loads(record["body"])
            job_id = env["job_id"]
            update(job_id, "running")
            code, result = call_deep2(env["request"])
            if 200 <= code < 300:
                update(job_id, "completed", result=result)
            else:
                update(job_id, "failed", result=result, error=f"Deep2 HTTP {code}")
        except Exception as e:
            try:
                env = json.loads(record.get("body", "{}"))
                if env.get("job_id"):
                    update(env["job_id"], "failed", error=str(e))
            except Exception:
                pass
            print(json.dumps({"message_id": msg_id, "error": str(e)}))
            failures.append({"itemIdentifier": msg_id})
    return {"batchItemFailures": failures}
