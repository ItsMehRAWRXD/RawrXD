# Stage G failure-gate tests against the real api Lambda handler (no Docker needed).
# Writes results to F:\~dev\_gate_g_results.txt
import json, os, importlib.util, time, sys

os.environ['RAWXD_BASE_URL'] = 'http://localhost:11435'
os.environ['RAWXD_UPSTREAM_KEY'] = 'rawrxd'
os.environ['CLIENT_API_KEY'] = 'test-key-1234567890'
os.environ['ALLOWED_ORIGIN'] = '*'
os.environ['JOBS_TABLE'] = 'test-jobs'
os.environ['JOB_QUEUE_URL'] = 'https://sqs.us-east-1.amazonaws.com/000/test'
os.environ['MAX_SYNC_TOKENS'] = '128'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

spec = importlib.util.spec_from_file_location(
    'api_app', r'F:\~dev\RawrXD_AWS_Serverless_Generative_AI\src\api\app.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

out = []
def log(s):
    out.append(s)
    print(s, flush=True)

# G4: real sync inference through handler with unique challenge
ch = 'RAWRXD_HANDLER_PROOF_' + str(int(time.time()))
ev4 = {'requestContext': {'http': {'method': 'POST', 'path': '/v1/chat/completions'}},
       'headers': {'x-rawrxd-key': 'test-key-1234567890'},
       'body': json.dumps({'model': 'qwen2.5-coder-1.5b-base',
                           'messages': [{'role': 'user', 'content': 'Reply with exactly: ' + ch}],
                           'max_tokens': 16, 'stream': False})}
r4 = m.handler(ev4, None)
d4 = json.loads(r4['body'])
toks = d4.get('usage', {}).get('completion_tokens', 0)
log(f"G4_SYNC status={r4['statusCode']} tokens={toks} challenge={ch}")
log('G4_PASS' if r4['statusCode'] == 200 and toks > 0 else 'G4_FAIL')

# G5: unreachable upstream fails honestly (health -> 503)
saved = m.BASE
m.BASE = 'http://localhost:19999'
r5 = m.handler({'requestContext': {'http': {'method': 'GET', 'path': '/health'}}}, None)
log(f"G5_UNREACHABLE status={r5['statusCode']} body={r5['body'][:70]}")
log('G5_PASS' if r5['statusCode'] == 503 else 'G5_FAIL')
m.BASE = saved

# G6: unauthorized /jobs access rejected
ev6 = {'requestContext': {'http': {'method': 'POST', 'path': '/jobs'}},
       'headers': {'x-rawrxd-key': 'bad'}, 'body': '{}'}
r6 = m.handler(ev6, None)
log(f"G6_JOBS_WRONG_KEY status={r6['statusCode']}")
log('G6_PASS' if r6['statusCode'] == 401 else 'G6_FAIL')

with open(r'F:\~dev\_gate_g_results.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(out) + '\n')