"""One bounded scheduled CPU/reference/GPU diagnostic, frozen output paths."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

root = Path(r'F:\rawrxd')
out = Path(__file__).resolve().parent
contract = json.loads((out/'DIAGNOSTIC_CONTRACT.json').read_text())
parser = argparse.ArgumentParser()
parser.add_argument('--name', default='bounded_pos0_7')
name = parser.parse_args().name
if not name.replace('_','').isalnum():
    raise SystemExit('invalid evidence directory name')
run = out/name
run.mkdir(exist_ok=False)
(run/'tokens.txt').write_text(' '.join(map(str,contract['teacher_forced_tokens'])))
environment = os.environ.copy()
environment['PATH'] = str(root/'build_ggml_profiler/bin/Release')+';'+environment['PATH']
for name in ['DEEP2_KV_F32','RR_GPU_CHECK','DEEP2_NO_DOT_BATCH','RR_NO_MOE_BATCH']:
    environment.pop(name,None)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def processes():
    ps = "Get-CimInstance Win32_Process -Filter \"Name='deep2_strata_bench.exe' OR Name='deep2_bench_tps.exe' OR Name='deep2_parity_trace.exe' OR Name='llama_dump_logits_teacher_forced.exe'\" | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Depth 4 -Compress"
    p = subprocess.run(['powershell','-NoProfile','-Command',ps],capture_output=True,text=True)
    return json.loads(p.stdout) if p.stdout.strip() else []


manifest = {'contract_sha256':sha(out/'DIAGNOSTIC_CONTRACT.json'),
            'head':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),
            'pre_processes':processes(),'runs':[],
            'sha256':{str(root/'src/deep2/runtime_graph_executor.cpp'):sha(root/'src/deep2/runtime_graph_executor.cpp'),
                      str(Path(contract['deep2'])):sha(contract['deep2']),
                      str(Path(contract['reference'])):sha(contract['reference'])}}
(run/'manifest.json').write_text(json.dumps(manifest,indent=2))
if manifest['pre_processes']:
    raise SystemExit('Competing benchmark processes present; no run started')
model = contract['model']
tokens = ' '.join(map(str,contract['teacher_forced_tokens']))
commands = [('reference',[contract['reference'],model,str(run/'tokens.txt'),str(run/'reference'), '32000']),
            ('cpu',[contract['deep2'],'--model',model,'--tokens',tokens,'--outdir',str(run/'cpu')]),
            ('gpu',[contract['deep2'],'--model',model,'--tokens',tokens,'--outdir',str(run/'gpu'),'--gpu'])]
for tag,args in commands:
    before = processes()
    if before:
        raise SystemExit('Contending process before '+tag)
    start = time.perf_counter()
    with (run/(tag+'.log')).open('w') as stream:
        result = subprocess.run(args,cwd=root,env=environment,stdout=stream,stderr=subprocess.STDOUT,timeout=90)
    item = {'tag':tag,'args':args,'exit_code':result.returncode,'wall_s':time.perf_counter()-start,
            'pre_processes':before,'post_processes':processes()}
    manifest['runs'].append(item)
    print(json.dumps(item),flush=True)
    (run/'manifest.json').write_text(json.dumps(manifest,indent=2))
    if result.returncode:
        raise SystemExit(result.returncode)
manifest['post_processes'] = processes()
(run/'manifest.json').write_text(json.dumps(manifest,indent=2))
print('Frozen run complete:',run)
