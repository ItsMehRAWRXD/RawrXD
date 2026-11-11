#!/usr/bin/env python3
"""Independent full-logit A/B grader; pure Python 3 standard library.
Usage: py -3 tools/compare_parity.py --reference REF --baseline BASE --candidate CAND --count 20
Inputs: unframed little-endian f32 vocab logits named ref_logits_posN.bin
and native_tf_logits_posN.bin. Missing files, invalid sizes, NaN, or Inf = FAIL.
"""
import argparse
from array import array
import hashlib
import json
import math
import re
from pathlib import Path
import struct
import sys

VOCAB=102400
BYTES=VOCAB*4

def read(path):
    data=path.read_bytes()
    if len(data)!=BYTES:
        raise ValueError(f'{path}: {len(data)} bytes, expected {BYTES}')
    a=array('f')
    a.frombytes(data)
    if sys.byteorder!='little':a.byteswap()
    if any(not math.isfinite(f) for f in a):
        raise ValueError(f'{path}: nonfinite value')
    return a

def metrics(ref, got):
    nr=sum(float(x)*x for x in ref)
    ng=sum(float(x)*x for x in got)
    cosine=sum(float(x)*y for x,y in zip(ref,got))/math.sqrt(nr*ng) if nr*ng else 0.0
    diff=[float(x)-y for x,y in zip(got,ref)]
    rmse=math.sqrt(sum(x*x for x in diff)/VOCAB)
    # First maximum ties match native SampleToken's strict '>' semantics.
    ai=max(range(VOCAB),key=got.__getitem__)
    ri=max(range(VOCAB),key=ref.__getitem__)
    top=sorted(range(VOCAB),key=got.__getitem__,reverse=True)[:10]
    rt=sorted(range(VOCAB),key=ref.__getitem__,reverse=True)[:10]
    return dict(native_argmax=ai,reference_argmax=ri,argmax_match=(ai==ri),
                cosine=cosine,rmse=rmse,max_abs=max(abs(v) for v in diff),
                top10_overlap=len(set(top)&set(rt)),
                reference_l1=float(ref[1]),reference_l185=float(ref[185]),
                native_l1=float(got[1]),native_l185=float(got[185]),
                reference_margin_185_minus_1=float(ref[185]-ref[1]),
                native_margin_185_minus_1=float(got[185]-got[1]))

def run(refroot, root, count):
    rows=[]
    for pos in range(count):
        ref=read(refroot/f'ref_logits_pos{pos}.bin')
        got=read(root/f'native_tf_logits_pos{pos}.bin')
        row=metrics(ref,got)
        row['position']=pos
        rows.append(row)
    return dict(count=count,
        matches=sum(int(r['argmax_match']) for r in rows),
        mean_cosine=sum(r['cosine'] for r in rows)/count,
        min_cosine=min(r['cosine'] for r in rows),
        max_rmse=max(r['rmse'] for r in rows),
        mismatches=[r['position'] for r in rows if not r['argmax_match']],
        rows=rows)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--count',type=int,default=20)
    p.add_argument('--require-packed-counter',action='store_true')
    p.add_argument('--output',type=Path,default=None)
    args=p.parse_args()
    if not 1<=args.count<=4096:raise ValueError('invalid count')
    baseline=run(args.reference,args.baseline,args.count)
    candidate=run(args.reference,args.candidate,args.count)
    counter_proof=None
    if args.require_packed_counter:
        log=args.candidate/'run.log'
        if not log.is_file(): raise ValueError('missing candidate run.log; packed path not verified')
        matches=list(re.finditer(
            r'\[PARITY_PACKED_DOT\] q4_calls=(\d+) q6_calls=(\d+) rows=(\d+) packed_bytes=(\d+)',
            log.read_text(encoding='utf-8',errors='replace')))
        if not matches: raise ValueError('no real packed-dot counter receipt in candidate run.log')
        m=matches[-1]
        counter_proof={'q4_calls':int(m.group(1)), 'q6_calls':int(m.group(2)),
                       'rows':int(m.group(3)), 'packed_bytes':int(m.group(4))}
        if counter_proof['q4_calls']+counter_proof['q6_calls']<=0 or counter_proof['rows']==0:
            raise ValueError('packed path was never executed')
    # Require no regression on ANY of the certified A/B quality metrics.
    # A candidate that improves only token ranking while hurting numeric
    # accuracy fails closed; fix should explain and improve both.
    epsilon=1e-12
    improves=(candidate['matches']>baseline['matches'] or
              (candidate['matches']==baseline['matches'] and
               candidate['mean_cosine']>baseline['mean_cosine']+epsilon))
    nonregresses=(candidate['matches']>=baseline['matches'] and
                  candidate['mean_cosine']>=baseline['mean_cosine']-epsilon and
                  candidate['min_cosine']>=baseline['min_cosine']-epsilon and
                  candidate['max_rmse']<=baseline['max_rmse']+epsilon)
    result={
        'certificate_id':'RAWRXD_DEEP2_PACKED_DOT_AB_001',
        'reference_dir':str(args.reference),
        'baseline_dir':str(args.baseline),
        'candidate_dir':str(args.candidate),
        'baseline':baseline,'candidate':candidate,
        'packed_execution_counters':counter_proof,
        'delta_matches':candidate['matches']-baseline['matches'],
        'delta_mean_cosine':candidate['mean_cosine']-baseline['mean_cosine'],
        'delta_min_cosine':candidate['min_cosine']-baseline['min_cosine'],
        'delta_max_rmse':candidate['max_rmse']-baseline['max_rmse'],
        'promotable': bool(improves and nonregresses),
        'verdict':'PROMOTION_CANDIDATE' if improves and nonregresses else 'RETAIN_CERTIFIED_A',
    }
    # A/B run does not certify 64 positions if fewer than 64 supplied.
    result['full_64_position_gate']='NOT_RUN' if args.count<64 else ('CANDIDATE_ONLY' if result['promotable'] else 'FAIL')
    print(f'BASE {baseline["matches"]}/{args.count} mean={baseline["mean_cosine"]:.8f} min={baseline["min_cosine"]:.8f} maxRMSE={baseline["max_rmse"]:.8f}')
    print(f'PACK {candidate["matches"]}/{args.count} mean={candidate["mean_cosine"]:.8f} min={candidate["min_cosine"]:.8f} maxRMSE={candidate["max_rmse"]:.8f}')
    for name,rows in [('BASE',baseline['rows']),('PACK',candidate['rows'])]:
        r=rows[1] if len(rows)>1 else rows[0]
        print(f'{name} pos{r["position"]} argmax={r["native_argmax"]} ref={r["reference_argmax"]} '
              f'margin185-1={r["native_margin_185_minus_1"]:.8f} '
              f'ref_margin185-1={r["reference_margin_185_minus_1"]:.8f}')
    print('VERDICT='+result['verdict'])
    if counter_proof:print('PACKED_EXECUTION_PROVEN='+str(counter_proof))
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    else:
        print(json.dumps(result,indent=2))
    return 0 if result['promotable'] else 2

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as ex:
        print('COMPARISON_FAIL_CLOSED:',ex,file=sys.stderr)
        sys.exit(1)
