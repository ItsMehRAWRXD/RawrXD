import json, os, importlib.util, time
os.environ['RAWXD_BASE_URL']='http://localhost:11435'
os.environ['RAWXD_UPSTREAM_KEY']='rawrxd'
os.environ['CLIENT_API_KEY']='test-key-1234567890'
os.environ['ALLOWED_ORIGIN']='*'
os.environ['JOBS_TABLE']='test-jobs'
os.environ['JOB_QUEUE_URL']='https://sqs.us-east-1.amazonaws.com/000/test'
os.environ['MAX_SYNC_TOKENS']='128'
spec = importlib.util.spec_from_file_location('api_app', r'F:\~dev\RawrXD_AWS_Serverless_Generative_AI\src\api\app.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ch = 'RAWRXD_HANDLER_RETRY2_' + str(int(time.time()))
ev = {'requestContext':{'http':{'method':'POST','path':'/v1/chat/completions'}},'headers':{'x-rawrxd-key':'test-key-1234567890'},'body':json.dumps({'model':'qwen2.5-coder-1.5b-base','messages':[{'role':'user','content':'Reply with exactly: '+ch}],'max_tokens':16,'stream':False})}
r = m.handler(ev, None)
d = json.loads(r['body'])
print('G4_RETRY2', r['statusCode'], 'tokens=', d.get('usage',{}).get('completion_tokens'), 'challenge=', ch)
