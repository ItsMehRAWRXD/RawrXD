import json, collections
man = json.load(open(r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1\manifest.json'))
# count ops by name at layer 0 and 1
c = collections.Counter()
for r in man:
    if r.get('position') != 1:
        continue
    c[(r.get('layer_idx'), r.get('op_name'))] += 1
# summarise per-block op-name multiset for the first 3 blocks
for blk in [0, 1, 2]:
    names = collections.Counter()
    for (l, n), k in c.items():
        if l == blk:
            names[n] += 1
    print('layer', blk, dict(names))