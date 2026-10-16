#!/usr/bin/env python3
"""Offline, dependency-free evidence gate for RawrXD agent receipts.
Does not confuse mock tests with real-model tests. No mutation of project files.
"""
import argparse, json, pathlib, sys, collections

def evaluate(path):
    events=[]; errors=[]
    try:
        for n,line in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
            if not line.strip(): continue
            e=json.loads(line)
            if not isinstance(e,dict) or not isinstance(e.get('kind'),str): errors.append(f'line {n}: invalid event')
            else: events.append(e)
    except (OSError,UnicodeError,ValueError) as ex: return {'file':str(path),'pass':False,'errors':[str(ex)]}
    kinds=[e['kind'] for e in events]; counts=collections.Counter(kinds)
    starts=counts['START']; terminal=[k for k in kinds if k in ('VERIFIED_SUCCESS','COMPLETED_UNVERIFIED','BLOCKED')]
    if starts!=1: errors.append(f'expected 1 START, got {starts}')
    if len(terminal)!=1: errors.append(f'expected 1 terminal event, got {terminal}')
    if terminal and kinds[-1]!=terminal[0]: errors.append('terminal event is not last')
    if not counts['MODEL']: errors.append('no model round trips')
    if terminal!=['VERIFIED_SUCCESS']: errors.append('no VERIFIED_SUCCESS receipt')
    if not counts['TOOL_verify']: errors.append('no verify tool event')
    if not counts['TOOL_edit'] and not counts['TOOL_write']: errors.append('no source mutation receipt')
    if not counts['TOOL_exec']: errors.append('no build/execution receipt')
    for e in events:
        if e['kind']=='TOOL_verify' and not e.get('ok'): errors.append('verification tool failed')
    if counts['REJECT'] and any('gash' in str(e.get('detail','')) for e in events if e['kind']=='REJECT'):
        # A rejected hallucinated tool is safe; execution is not.
        if any(e['kind']=='TOOL_gash' for e in events): errors.append('invalid gash tool was executed')
    return {'file':str(path),'pass':not errors,'errors':errors,'events':len(events),'terminal':terminal[0] if terminal else None,'counts':dict(counts)}

def main():
    ap=argparse.ArgumentParser(description='RawrXD production evidence checker; real model ledgers only')
    ap.add_argument('ledgers',nargs='+',type=pathlib.Path)
    ap.add_argument('--min-pass-rate',type=float,default=0.9)
    ap.add_argument('--min-tasks',type=int,default=10)
    ap.add_argument('--report',type=pathlib.Path)
    args=ap.parse_args()
    if not 0<=args.min_pass_rate<=1 or args.min_tasks<1: ap.error('invalid thresholds')
    results=[evaluate(p) for p in args.ledgers]
    passed=sum(r['pass'] for r in results)
    rate=passed/len(results)
    gate=len(results)>=args.min_tasks and rate>=args.min_pass_rate
    report={'gate':'RAWR_PARITY_REAL_MODEL','pass':gate,'tasks':len(results),'passed':passed,'pass_rate':round(rate,4),'min_tasks':args.min_tasks,'min_pass_rate':args.min_pass_rate,'results':results,'warning':'Ledger consistency does not independently establish patch correctness; review diffs and test quality.'}
    if args.report: args.report.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if gate else 1
if __name__=='__main__':sys.exit(main())
