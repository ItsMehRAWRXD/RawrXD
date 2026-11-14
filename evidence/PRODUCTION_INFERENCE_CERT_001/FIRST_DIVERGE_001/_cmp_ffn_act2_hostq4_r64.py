import os, glob, struct, math, re
from datetime import datetime
ev = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"
gpu = os.path.join(ev, "stage_dump_ffn_act2_hostq4_r64")
ref = os.path.join(ev, "stage_dump_ffn_act2_c740_after_ref")
seal_gpu = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
ABS_TOL=1e-5; REL_TOL=1e-4; BEFORE=4.577637e-05
PROBES=[
 ("FFN_GATE_2","deep2_FFN_GATE_2_pos0_layer0_full_n5632_*.bin","llama_FFN_GATE_2_pos0_layer0_full_n5632_*.bin"),
 ("FFN_UP_2","deep2_FFN_UP_2_pos0_layer0_full_n5632_*.bin","llama_FFN_UP_2_pos0_layer0_full_n5632_*.bin"),
 ("FFN_ACT_2","deep2_FFN_ACT_2_pos0_layer0_full_n5632_*.bin","llama_FFN_ACT_2_pos0_layer0_full_n5632_*.bin"),
]
def load(p):
 b=open(p,"rb").read(); n=len(b)//4; return struct.unpack("<%df"%n,b),b
def fnv(data):
 h=0xCBF29CE484222325
 for c in data:
  h^=c; h=(h*0x100000001B3)&0xFFFFFFFFFFFFFFFF
 return f"{h:016x}"
def stats(a,b,abs_tol):
 n=min(len(a),len(b)); s=0.0; mx=0.0; n_gt=0; peak_i=-1
 for i in range(n):
  d=abs(a[i]-b[i]); s+=d*d
  if d>mx: mx=d; peak_i=i
  if d>abs_tol: n_gt+=1
 l2b=math.sqrt(sum(x*x for x in b[:n])); rms=math.sqrt(s/n) if n else 0.0
 rel=rms/(l2b+1e-30)
 return n,rms,rel,mx,n_gt,peak_i
def seqnum(p):
 m=re.search(r"seq(\d+)",os.path.basename(p)); return int(m.group(1)) if m else 999999
def pick(d,pat):
 gs=glob.glob(os.path.join(d,pat)); return sorted(gs,key=seqnum)[0] if gs else None
lines=[]
lines.append("GPU_PARITY_FFN_ACT_2_REMEDIATE_001.hostq4_r64.compare")
lines.append("PAIR=stage_dump_ffn_act2_hostq4_r64 vs stage_dump_ffn_act2_c740_after_ref")
lines.append("EXE=build_ninja/bin/rawr_gpufwd_ffn_act2_hostq4.exe SHA256=3892009339AE6CB6… FORCE_VULKAN PARITY=0 HOST_Q4_FFN_UNDER_FORCE=1")
lines.append(f"ASOF={datetime.now().isoformat(timespec='seconds')}")
lines.append(f"ABS_TOL={ABS_TOL:g} REL_TOL={REL_TOL:g}")
lines.append(f"BEFORE_maxAbs_FFN_ACT_2={BEFORE:.6e}")
act_mx=None; results={}
for name,gpat,rpat in PROBES:
 gp=pick(gpu,gpat); rp=pick(ref,rpat)
 if not gp or not rp:
  lines.append(f"{name}: MISSING g={bool(gp)} r={bool(rp)}"); continue
 a,ra=load(gp); b,rb=load(rp)
 n,rms,rel,mx,n_gt,peak_i=stats(a,b,ABS_TOL)
 fg,fr=fnv(ra),fnv(rb)
 material=(mx>ABS_TOL) or (rel>REL_TOL)
 kind="EXACT" if fg==fr else ("MATERIAL_DIVERGENCE" if material else "BITWISE_DIFF")
 under="Y" if not material else "N"
 lines.append(f"{name}: kind={kind} maxAbs={mx:.6e} rel_rms={rel:.6e} n_gt_abs={n_gt}/{n} UNDER_TOL={under} peak_i={peak_i} gpu[{peak_i}]={a[peak_i]:.9e} ref[{peak_i}]={b[peak_i]:.9e} gpu_fnv={fg} ref_fnv={fr}")
 results[name]=(mx,material,under)
 if name=="FFN_ACT_2": act_mx=mx
if act_mx is None:
 lines += ["AFTER_maxAbs_FFN_ACT_2=NOT_RUN","UNDER_TOL=N","RUNTIME_REACHED=0"]
else:
 lines.append(f"AFTER_maxAbs_FFN_ACT_2={act_mx:.6e}")
 lines.append(f"UNDER_TOL={results['FFN_ACT_2'][2]}")
 lines.append("RUNTIME_REACHED=1")
 lines.append(f"DELTA_vs_BEFORE={act_mx-BEFORE:.6e}")
under_y = results.get("FFN_ACT_2",(0,True,"N"))[2]=="Y"
lines.append(f"MATCH_PASS={1 if under_y else 0}")
lines += ["INVENT_PASS=0","PROMOTE=0","TIP_CLIMB=HOLD","TIP_BIND=6754616E","CLI_BOARD_TIP_PIN=15A119D1","C740_PIN_UNTOUCHED=1","NO_CLASS_TOL_PCT=1"]
text="\n".join(lines)+"\n"
for p in [os.path.join(ev,"GPU_PARITY_FFN_ACT_2_REMEDIATE_001.hostq4_r64.compare.txt"), os.path.join(seal_gpu,"GPU_PARITY_FFN_ACT_2_REMEDIATE_001.hostq4_r64.compare.txt")]:
 open(p,"w",encoding="utf-8").write(text); print("WROTE",p)
print(text)
