import json
man = json.load(open(r'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1\manifest.json'))
for r in man:
    if r.get('layer_idx') == 0 and r.get('position') == 1 and r.get('tensor_type') in ('weight','w'):
        print({k: r.get(k) for k in ('index','op_id','layer_idx','position','op_name','tensor_type','num_elements','shape')})