import json, os, struct
import numpy as np

base = r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001'
native = json.load(open(os.path.join(base, 'native.json'), 'r'))

# native logits here are only the first 8 of each position (that's what the dump writes).
# The harness also writes full logits implicitly via argmax, so compare argmax first.
nat_arg = native['argmax']
print('native argmax per position (%d):' % len(nat_arg))
print(nat_arg)

# reference argmax from the *original certified* native_vs_reference comparison files
refdir = r'F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced'
ref_arg = []
for pos in range(len(nat_arg)):
    p = os.path.join(refdir, 'ref_logits_pos%d.bin' % pos)
    if not os.path.isfile(p):
        break
    raw = open(p, 'rb').read()
    vals = np.frombuffer(raw, dtype=np.float32)
    ref_arg.append(int(vals.argmax()))

print('\nreference argmax (%d):' % len(ref_arg))
print(ref_arg)

n = min(len(nat_arg), len(ref_arg))
match = sum(1 for i in range(n) if nat_arg[i] == ref_arg[i])
print('\nARGMAX MATCH vs llama.cpp reference: %d/%d = %.1f%%' % (match, n, 100.0 * match / max(n, 1)))

# first 8 logits comparison
print('\nfirst-8 logits (native vs reference):')
for pos in range(min(4, n)):
    refp = os.path.join(refdir, 'ref_logits_pos%d.bin' % pos)
    rv = np.frombuffer(open(refp, 'rb').read(), dtype=np.float32)[:8]
    nv = native['logits'][pos]
    print('  pos %d native=%s ref=%s' % (pos, ['%.5f' % x for x in nv], ['%.5f' % x for x in rv[:len(nv)]]))
