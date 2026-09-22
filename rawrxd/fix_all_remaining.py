import re

filepath = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# List of files confirmed missing (from configure error log)
missing_files = [
    'src/deep2/deep2_k2_logits_climb_cert.cpp',
    'src/deep2/deep2_k2_trygpu_logits_split_cert.cpp',
    'src/deep2/deep2_k2_logits_gpu_range_attribution_001.cpp',
    'src/deep2/rawrxd_run_modelname_001.cpp',
    'src/deep2/rawr_run.cpp',
    'src/deep2/deep2_k2_useful_tps_001.cpp',
    'src/deep2/rawrxd_normal_gguf_final_001.cpp',
    'src/deep2/deep2_k2_tps_rainbow_cert.cpp',
    'src/deep2/deep2_k2_gpu_mla_slot_reuse_cert.cpp',
    'src/deep2/deep2_nu_live_consumer_cert.cpp',
    'src/deep2/deep2_k2_gpu_mla_nu_bridge_cert.cpp',
    'src/deep2/deep2_nu_gemv_parity_cert.cpp',
    'src/deep2/deep2_nu_gpu_gemv_cert.cpp',
    'src/rkc/rkc_deep2_model_authority_cert.cpp',
]

for mf in missing_files:
    idx = content.find(mf)
    if idx == -1:
        print(f'  Not found: {mf}')
        continue
    # Find nearest preceding if(BUILD_ or if(BUILD_RAWRXD
    before = content[:idx]
    last_if = before.rfind('if(BUILD_')
    if last_if == -1:
        # Some certs are nested under another if(); try generic if(
        last_if = before.rfind('if(')
    if last_if == -1:
        print(f'  No if found before: {mf}')
        continue
    # find end of if line
    if_end = before.find(')', last_if)
    if if_end == -1:
        print(f'  Unclosed if before: {mf}')
        continue
    if_line = before[last_if:if_end+1]
    if if_line.startswith('if(0)'):
        print(f'  Already disabled: {mf}')
        continue
    content = before[:last_if] + f'if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: {mf}' + before[if_end+1:] + content[idx:]
    print(f'  Disabled block for: {mf}')

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Done')
