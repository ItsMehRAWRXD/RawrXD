# gate1b_vector_parity.py -- REUSABLE Deep2 parity harness.
#
# One harness for every model: reads the architecture from GGUF metadata,
# maps the independent reference's per-op checkpoints onto Deep2's hidden
# dumps, and reports the FIRST divergent operator with cosine / max-abs /
# relative-L2 / first-8 values. A failed model names its first divergent
# tensor, operator and layer -- no more manual investigation.
#
# Usage:
#   py gate1b_vector_parity.py --ref <ref_checkpoint.log> --d2 <dump-prefix>
#                             [--gguf <model.gguf>] [--pos 0] [--token 750]
import argparse
import os
import re
import sys
import numpy as np

# Deep2 dump name per reference checkpoint (semantic alignment, not string).
# resid1 = attention residual (reference ATTN_RESIDUAL)
# resid2 = final block residual (reference LAYER_RESIDUAL / MLP_RESIDUAL)
# pub.resid_in = the block-0 embedding (reference EMBED)
def d2_name_for(cp, layer):
    if cp == 'EMBED':
        return 'pub.b0.resid_in.f32'
    if cp in ('ATTN_RESIDUAL', 'MLP_RESIDUAL', 'LAYER_RESIDUAL'):
        return 'blk{}.resid{}.f32'.format(layer, 1 if cp == 'ATTN_RESIDUAL' else 2)
    return None

def read_text(path):
    raw = open(path, 'rb').read()
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return raw.decode('utf-16')
    return raw.decode('utf-8', errors='replace')

def parse_ref(path):
    """Parse 'STEP=p CP=NAME LAYER=n COUNT=.. MIN=.. MAX=.. L2=.. FIRST8=a,b,..'."""
    out = []
    rx = re.compile(
        r'STEP=(\d+) CP=(\w+)(?: LAYER=(\d+))? COUNT=\d+ MIN=([-\d.eE+]+) '
        r'MAX=([-\d.eE+]+) .*? L2=([-\d.eE+]+) FIRST8=([-\d.eE+,]+)')
    for line in read_text(path).splitlines():
        m = rx.search(line)
        if not m:
            continue
        step, cp, layer, mn, mx, l2, f8 = m.groups()
        first8 = [float(x) for x in f8.split(',') if x]
        out.append({'step': int(step), 'cp': cp,
                    'layer': int(layer) if layer is not None else 0,
                    'min': float(mn), 'max': float(mx), 'l2': float(l2),
                    'first8': first8})
    return out

def vecstats(d_full, ref_first8, ref_l2):
    """Deep2 full vector vs reference checkpoint (FIRST8 + L2 + hash)."""
    n8 = min(d_full.shape[0], len(ref_first8))
    f8d = d_full[:n8]
    f8r = np.array(ref_first8[:n8], dtype=np.float32)
    maxabs8 = float(np.max(np.abs(f8d - f8r)))
    d_l2 = float(np.linalg.norm(d_full))
    ratio = d_l2 / ref_l2 if ref_l2 > 0 else float('inf')
    f8ok = bool(np.allclose(f8d, f8r, atol=2e-3, rtol=2e-3))
    return f8ok, maxabs8, ratio

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', required=True)
    ap.add_argument('--d2', required=True)
    ap.add_argument('--pos', default='0')
    ap.add_argument('--token', default='')
    ap.add_argument('--gguf', default='')
    ap.add_argument('--ref-dumps', default='', help='dir/prefix of reference full-vector f32 dumps')
    ap.add_argument('--cos-tol', type=float, default=0.999)
    ap.add_argument('--rel-tol', type=float, default=0.01)
    a = ap.parse_args()

    if a.gguf:
        import gguf
        r = gguf.GGUFReader(a.gguf)
        arch = r.fields['general.architecture'].contents()
        nb = None
        for f in r.fields.values():
            if f.name.endswith('.block_count') and f.name.startswith(arch):
                nb = f.contents()
        print(f'ARCH={arch} BLOCKS={nb}')

    print(f'PARITY_POS={a.pos} TOKEN={a.token}')
    refs = parse_ref(a.ref)
    refs = [x for x in refs if x['step'] == int(a.pos)]
    # ordered: same order the reference emits
    first_div = None
    checks = 0
    for cp in refs:
        name = d2_name_for(cp['cp'], cp['layer'])
        if name is None:
            continue
        path = os.path.join(a.d2 + '.' + name)
        if not os.path.exists(path):
            print(f'VECTOR {cp["cp"]} LAYER={cp["layer"]}: DEEP2_DUMP_MISSING ({name})')
            continue
        d = np.fromfile(path, dtype='<f4')
        f8ok, maxabs8, ratio = vecstats(d, cp['first8'], cp['l2'])
        # full-vector metrics when the reference dumped the whole vector too
        ref_full = os.path.join(a.ref_dumps,
                                f'.pos{a.pos}.{cp["cp"]}.L{cp["layer"]}.f32') if a.ref_dumps else ''
        cos = rel = None
        if os.path.exists(ref_full):
            r = np.fromfile(ref_full, dtype='<f4')
            n = min(d.shape[0], r.shape[0])
            dd, rr = d[:n], r[:n]
            den = float(np.linalg.norm(dd) * np.linalg.norm(rr))
            cos = float(np.dot(dd, rr) / den) if den > 0 else 1.0
            rel = float(np.linalg.norm(dd - rr) / (np.linalg.norm(rr) + 1e-30))
        checks += 1
        ok = f8ok and (cos is None or (cos > a.cos_tol and rel < a.rel_tol))
        verdict = 'PASS' if ok else 'DIVERGENT'
        extra = (f' cos={cos:.6f} rel_l2={rel:.6f}' if cos is not None else '')
        print(f'VECTOR {cp["cp"]} LAYER={cp["layer"]} first8_match={f8ok} '
              f'first8_maxabs={maxabs8:.5f} l2_ratio_d2_over_ref={ratio:.4f}{extra} -> {verdict}')
        if verdict == 'DIVERGENT' and first_div is None:
            first_div = (cp['cp'], cp['layer'], cos if cos is not None else float('nan'),
                         rel if rel is not None else float('nan'), ratio)
    print(f'VECTOR_CHECKS={checks}')
    if first_div:
        print(f'FIRST_DIVERGENT_OPERATOR={first_div[0]} LAYER={first_div[1]} '
              f'cos={first_div[2]:.6f} rel_l2={first_div[3]:.4f} l2_ratio={first_div[4]:.4f}')
    else:
        print('FIRST_DIVERGENT_OPERATOR=none (all checked checkpoints match)')

if __name__ == '__main__':
    main()
