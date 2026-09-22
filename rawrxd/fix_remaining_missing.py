import re

filepath = r'f:\~dev\rawrxd\CMakeLists.txt'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove missing source files from lists
missing_sources = [
    'src/security/InputSanitizer.cpp',
    'src/agentic/AgentOllamaClient.cpp',
    'src/asm/rawr_globals.asm',
    'src/asm/RawrXD_PE_Importer.asm',
]
for src in missing_sources:
    # Remove lines that contain the source file (strip trailing whitespace and comment if needed)
    # Pattern: line with optional whitespace, then the source file, optional comment
    content = re.sub(r'^[ \t]*' + re.escape(src) + r'(?:\s*#.*)?\r?\n', '', content, flags=re.MULTILINE)

# 2. Disable certification executables for missing files
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
    # Find the add_executable block that references this cert file.
    # Pattern: option(BUILD_XYZ "..." ON)\nif(BUILD_XYZ)\n    add_executable(cert_name\n        src/deep2/cert_file\n    ...\nendif()
    # We will replace `if(BUILD_...)` with `if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: src/deep2/...`
    # The regex needs to match the specific if line preceding the add_executable that contains the cert.
    # This is tricky because the if line can be long. Use a simpler approach:
    # Find the add_executable line containing the cert filename, then backtrack to the nearest preceding `if(BUILD_`
    pass

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('Step 1 done')
