import re

filepath = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

missing_certs = [
    'deep2_live_path_effectiveness_cert.cpp',
    'deep2_live_path_interaction_bounds_cert.cpp',
    'deep2_k2_full_depth_effectiveness_cert.cpp',
    'deep2_k2_trampoline_full_depth_opt_cert.cpp',
    'deep2_k2_auto_workload_policy_cert.cpp',
    'deep2_k2_e2e_model_size_matrix_cert.cpp',
    'deep2_k2_live_generate_policy_cert.cpp',
    'deep2_k2_live_policy_split_cert.cpp',
    'deep2_k2_policy_hysteresis_cert.cpp',
    'deep2_k2_mla_rebench_promote_cert.cpp',
    'deep2_k2_mla_reuse_promote_cert.cpp',
    'deep2_k2_mla_full_depth_soak_cert.cpp',
    'deep2_k2_live_decode_mla_cert.cpp',
    'deep2_k2_mla_fused_q4kt_cert.cpp',
    'deep2_k2_shard_attn_residency_cert.cpp',
    'deep2_k2_logits_q6k_resident_cert.cpp',
    'deep2_k2_mla_kv_expand_cert.cpp',
    'deep2_k2_mla_kv_expand_opt_cert.cpp',
    'deep2_k2_mla_qkv_proj_cert.cpp',
    'deep2_k2_mla_qa_critical_cert.cpp',
    'deep2_ucf_bounce_smoke.cpp',
    'deep2_ucf_no_stale_dispatch_001.cpp',
    'deep2_ucf_read_converge_001.cpp',
    'deep2_ucf_logits_range_bounce_001.cpp',
    'deep2_ucf_semantic_abi_v1_cert.cpp',
    'deep2_ucf_generation_ticket_001.cpp',
    'deep2_ucf_gpu_ready_e2e.cpp',
    'deep2_ucf_bouncehouse_example.cpp',
    'deep2_ucf_halo_spark_001.cpp',
    'deep2_rmv_mount_001.cpp',
    'deep2_vwa_range_contract_001.cpp',
    'deep2_ucf_mobility_fault_001.cpp',
    'deep2_k2_semantic_seal_cert.cpp',
    'deep2_k2_serverless_stream_latency_cert.cpp',
    'deep2_k2_live_decode_sustained_cert.cpp',
    'deep2_k2_wall_attribution_cert.cpp',
]

for cert in missing_certs:
    # Pattern: find the if(BUILD_...) line that is immediately followed by add_executable containing the cert file.
    # We look for: if(BUILD_...)\n    add_executable( ... cert ...)
    # Replace the if line with if(0)
    pattern = r'(if\(BUILD_[^)]+\)\s*\n)(\s*add_executable\([^)]*' + re.escape(cert) + r')'
    def repl(m):
        return f'if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: src/deep2/{cert}\n{m.group(2)}'
    content_new = re.sub(pattern, repl, content)
    if content_new != content:
        content = content_new
    else:
        # Try a looser pattern: just look for if(BUILD_...) preceding the cert file within ~200 chars
        idx = content.find(cert)
        if idx != -1:
            # search backwards for if(BUILD_)
            before = content[:idx]
            last_if = before.rfind('if(BUILD_')
            if last_if != -1:
                # find end of if line
                if_end = before.find(')', last_if)
                if if_end != -1:
                    if_line = before[last_if:if_end+1]
                    # Verify the if line isn't already if(0)
                    if not if_line.startswith('if(0)'):
                        content = before[:last_if] + f'if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: src/deep2/{cert}\n' + before[if_end+1:] + content[idx:]
                        # print(f'Fixed via fallback: {cert}')

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Done disabling missing cert blocks')
