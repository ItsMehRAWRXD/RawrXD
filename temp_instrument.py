import re

path = r'f:\~dev\rawrxd\src\deep2\Deep2Engine.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'bool Deep2Engine::loadModel\(const std::string& ggufPath, ModelLoadDiag\* diag\) \{', text)
assert m, 'loadModel signature not found'
start = m.start()
brace = text.find('{', start)
assert brace != -1
end_match = re.search(r'\n(bool|void|int|size_t|std::vector|std::string|Deep2::|auto) [A-Za-z_]', text[brace+1:])
assert end_match
end = brace + 1 + end_match.start()
body = text[brace+1:end]

stages = [
    ('bindTensor shape overflow', 'BIND_SHAPE_OVERFLOW'),
    ('bindFirst token_embed', 'BIND_TOKEN_EMBED'),
    ('embedding geometry mismatch', 'EMBED_GEOMETRY'),
    ('invalid transformer head/layer geometry', 'HEAD_LAYER_GEOMETRY'),
    ('GGUF missing layer-norm epsilon', 'NORM_EPS_MISSING'),
    ('final norm / LM-head topology invalid', 'FINAL_NORM_LMHEAD'),
    ('layer norm tensors', 'LAYER_NORM_MISSING'),
    ('missing Q/K/V topology', 'QKV_TOPOLOGY_MISSING'),
    ('missing dense FFN tensors', 'DENSE_FFN_MISSING'),
    ('FFN geometry mismatch', 'FFN_GEOMETRY_MISMATCH'),
    ('attention projection geometry mismatch', 'ATTN_PROJECTION_GEOMETRY'),
    ('MoE router geometry mismatch', 'MOE_ROUTER_GEOMETRY'),
    ('missing routed expert tensors', 'MOE_EXPERT_TENSOR_MISSING'),
    ('incomplete expert set', 'MOE_INCOMPLETE_EXPERT_SET'),
    ('expert geometry mismatch', 'MOE_EXPERT_GEOMETRY_MISMATCH'),
    ('incomplete shared expert', 'MOE_SHARED_EXPERT_INCOMPLETE'),
    ('missing feed-forward geometry', 'FEED_FORWARD_GEOMETRY_MISSING'),
    ('invalid MoE metadata', 'MOE_METADATA_INVALID'),
    ('unsupported expert_gating_func', 'MOE_GATING_FUNC_UNSUPPORTED'),
    ('router initialization failed', 'MOE_ROUTER_INIT_FAILED'),
    ('expert byte overflow', 'MOE_EXPERT_BYTE_OVERFLOW'),
    ('neither complete dense nor MoE FFN', 'HYBRID_FFN_INCOMPLETE'),
    ('expert_count>0 but no MoE layer tensors', 'MOE_NO_LAYERS_BOUND'),
    ('initialize(recovered)', 'ENGINE_INIT_FAILED'),
    ('allocateBuffers', 'BUFFER_ALLOC_FAILED'),
    ('KV cache allocation failed', 'KV_CACHE_ALLOC_FAILED'),
]
patterns = {s:t for s,t in stages}

parts = body.split('return false;')
assert len(parts) > 1, 'No return false; found in body'
new_parts = [parts[0]]
code = 4
for i in range(1, len(parts)):
    preceding = parts[i-1]
    tag = 'UNKNOWN_STAGE'
    matched = False
    for snippet, t in patterns.items():
        if snippet in preceding:
            tag = t
            matched = True
            break
    if not matched:
        if 'bindTensor' in preceding:
            tag = 'BIND_TENSOR_GENERIC'
        elif 'bindFirst' in preceding:
            tag = 'BIND_FIRST_GENERIC'
        elif 'bindPackedExperts' in preceding:
            tag = 'BIND_PACKED_EXPERTS_GENERIC'
        elif 'bindSeparateExperts' in preceding:
            tag = 'BIND_SEPARATE_EXPERTS_GENERIC'
        elif 'bindExpertFamily' in preceding:
            tag = 'BIND_EXPERT_FAMILY_GENERIC'
        elif 'bindAny' in preceding:
            tag = 'BIND_ANY_GENERIC'
        else:
            tag = 'STAGE_' + str(code)
    block = f'''        if (diag) {{
            diag->stageCode = {code};
            diag->stageName = "{tag}";
            diag->message = "{tag}";
        }}
        return false;'''
    new_parts.append(block)
    new_parts.append(parts[i])
    code += 1

new_body = ''.join(new_parts)
new_text = text[:brace+1] + new_body + text[end:]
with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)
print(f'Done. Assigned stages {4}-{code-1}.')
