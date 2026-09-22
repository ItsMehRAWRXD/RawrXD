import re, os, sys

CMAKE = "f:/~dev/rawrxd/CMakeLists.txt"
ROOT = "f:/~dev/rawrxd"

with open(CMAKE, "r", encoding="utf-8") as f:
    content = f.read()

# 1) Remove RouterPrefetchTelemetry append
content = re.sub(
    r"# RouterPrefetchTelemetry is added to SOURCES after RAWR_ENGINE_SOURCES is captured;\n# add it explicitly here so RawrEngine links the telemetry definitions\.\nlist\(APPEND RAWR_ENGINE_SOURCES src/deep2/RouterPrefetchTelemetry\.cpp\)\n",
    "",
    content,
)

# 2) Filter OMEGA1_SOURCES
content = re.sub(
    r"(set\(OMEGA1_SOURCES\n    \$\{OMEGA1_DIR\}/OmegaPowerShellBridge\.cpp\n\)\n)",
    r"\1rawrxd_filter_missing_sources(OMEGA1_SOURCES)\n\n",
    content,
)

# 3) Filter RAWRXD_COMPRESSION_SOURCES
content = re.sub(
    r"(set\(RAWRXD_COMPRESSION_SOURCES\n    \$\{RAWRXD_COMPRESSION_DIR\}/zlib_runtime_loader\.cpp\n\)\n)",
    r"\1rawrxd_filter_missing_sources(RAWRXD_COMPRESSION_SOURCES)\n\n",
    content,
)

# 4) Guard K2LivePathTensorCache_Emit append
old_k2 = """list(APPEND INFERENCE_ENGINE_LIBRARY_SOURCES
    src/deep2/K2LivePathTensorCache_Emit.cpp)"""
new_k2 = """if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/K2LivePathTensorCache_Emit.cpp")
    list(APPEND INFERENCE_ENGINE_LIBRARY_SOURCES
        src/deep2/K2LivePathTensorCache_Emit.cpp)
endif()"""
content = content.replace(old_k2, new_k2)

# 5) Filter GOLD_UNDERSCORE_SOURCES and ASM_KERNEL_SOURCES before add_executable(RawrXD_Gold)
content = re.sub(
    r"(\nadd_executable\(RawrXD_Gold \$\{GOLD_UNDERSCORE_SOURCES\} \$\{ASM_KERNEL_SOURCES\}\)\n)",
    r"\nrawrxd_filter_missing_sources(GOLD_UNDERSCORE_SOURCES)\nrawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)\nadd_executable(RawrXD_Gold ${GOLD_UNDERSCORE_SOURCES} ${ASM_KERNEL_SOURCES})\n",
    content,
)

# 6) Filter ASM_KERNEL_SOURCES before Win32IDE copy
content = re.sub(
    r"(    # ADDR32 MASM objs cannot link with /LARGEADDRESSAWARE \(required for amdvlk\n    # ProductOpenSession \u2014 R01\)\. Drop them from IDE; feature flags already gate calls\.\n    set\(_WIN32IDE_ASM \$\{ASM_KERNEL_SOURCES\}\)\n)",
    r"    rawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)\n\1",
    content,
)

# 7) Disable DEEP2_R1_DECODE_SMOKE and DEEP2_OUTER_SMOKE (missing asm files)
content = re.sub(
    r'^(option\(BUILD_DEEP2_R1_DECODE_SMOKE "Build Deep2R1TensorDecode no-CRT smoke" ON\)\n)'
    r'^if\(BUILD_DEEP2_R1_DECODE_SMOKE\)\n',
    r'\1if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing asm files\n',
    content,
    flags=re.MULTILINE,
)
content = re.sub(
    r'^(option\(BUILD_DEEP2_OUTER_SMOKE "Build Deep2 outer shard-probe smoke" ON\)\n)'
    r'^if\(BUILD_DEEP2_OUTER_SMOKE\)\n',
    r'\1if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing asm files\n',
    content,
    flags=re.MULTILINE,
)

# 8) Certification blocks with known missing files -> if(0)
missing_certs = [
    "src/deep2/deep2_live_path_effectiveness_cert.cpp",
    "src/deep2/deep2_live_path_interaction_bounds_cert.cpp",
    "src/deep2/deep2_k2_full_depth_effectiveness_cert.cpp",
    "src/deep2/deep2_k2_trampoline_full_depth_opt_cert.cpp",
    "src/deep2/deep2_k2_auto_workload_policy_cert.cpp",
    "src/deep2/deep2_k2_e2e_model_size_matrix_cert.cpp",
    "src/deep2/deep2_k2_live_generate_policy_cert.cpp",
    "src/deep2/deep2_k2_live_policy_split_cert.cpp",
    "src/deep2/deep2_k2_policy_hysteresis_cert.cpp",
    "src/deep2/deep2_k2_mla_rebench_promote_cert.cpp",
    "src/deep2/deep2_k2_mla_reuse_promote_cert.cpp",
    "src/deep2/deep2_k2_mla_full_depth_soak_cert.cpp",
    "src/deep2/deep2_k2_live_decode_mla_cert.cpp",
    "certs/mla_cert_001.cpp",
    "src/deep2/deep2_k2_mla_fused_q4kt_cert.cpp",
    "src/deep2/deep2_k2_shard_attn_residency_cert.cpp",
    "src/deep2/deep2_k2_logits_q6k_resident_cert.cpp",
    "src/deep2/deep2_k2_mla_kv_expand_cert.cpp",
    "src/deep2/deep2_k2_mla_kv_expand_opt_cert.cpp",
    "src/deep2/deep2_k2_mla_qkv_proj_cert.cpp",
    "src/deep2/deep2_k2_mla_qa_critical_cert.cpp",
    "src/deep2/deep2_ucf_bounce_smoke.cpp",
    "src/deep2/deep2_ucf_no_stale_dispatch_001.cpp",
    "src/deep2/deep2_ucf_read_converge_001.cpp",
    "src/deep2/deep2_ucf_logits_range_bounce_001.cpp",
    "src/deep2/deep2_ucf_semantic_abi_v1_cert.cpp",
    "src/deep2/deep2_ucf_generation_ticket_001.cpp",
    "src/deep2/deep2_ucf_gpu_ready_e2e.cpp",
    "src/deep2/deep2_ucf_bouncehouse_example.cpp",
    "src/deep2/deep2_ucf_halo_spark_001.cpp",
    "src/deep2/deep2_rmv_mount_001.cpp",
    "src/deep2/deep2_vwa_range_contract_001.cpp",
    "src/deep2/deep2_ucf_mobility_fault_001.cpp",
    "src/deep2/deep2_k2_semantic_seal_cert.cpp",
    "src/deep2/deep2_k2_serverless_stream_latency_cert.cpp",
    "src/deep2/deep2_k2_live_decode_sustained_cert.cpp",
    "src/deep2/deep2_k2_wall_attribution_cert.cpp",
    "src/deep2/deep2_k2_logits_climb_cert.cpp",
    "src/deep2/deep2_k2_trygpu_logits_split_cert.cpp",
    "src/deep2/deep2_k2_logits_gpu_range_attribution_001.cpp",
    "src/deep2/rawrxd_run_modelname_001.cpp",
    "src/deep2/rawr_run.cpp",
    "src/deep2/deep2_k2_useful_tps_001.cpp",
    "src/deep2/rawrxd_normal_gguf_final_001.cpp",
    "src/deep2/deep2_k2_tps_rainbow_cert.cpp",
    "src/deep2/deep2_k2_gpu_mla_slot_reuse_cert.cpp",
    "src/deep2/deep2_nu_live_consumer_cert.cpp",
    "src/deep2/deep2_k2_gpu_mla_nu_bridge_cert.cpp",
    "src/deep2/deep2_nu_perf_cert.cpp",
    "src/deep2/deep2_nu_gemv_parity_cert.cpp",
    "src/deep2/deep2_nu_gpu_gemv_cert.cpp",
    "src/rkc/rkc_deep2_model_authority_cert.cpp",
    "src/rkc/rkc_model_inventory_cert.cpp",
    "src/rkc/rkc_negative_knowledge_cert.cpp",
    "src/deep2/Deep2Benchmark.cpp",
]

for cpp_rel in missing_certs:
    # Build a regex that captures option(...)/if(...)/add_executable(...)/.../endif()
    # We need to be tolerant of extra lines (target_link_libraries, target_compile_options, target_include_directories, set_target_properties, optional message(STATUS))
    # Use a non-greedy match from add_executable to endif()
    pattern = re.compile(
        r'^(option\(BUILD_[A-Z0-9_]+ "[^"]*" ON\)\n)'
        r'^(if\(BUILD_[A-Z0-9_]+\)\n)'
        r'^(    add_executable\(\s*\w+\s*\n'
        r'        ' + re.escape(cpp_rel) + r'\n'
        r'    \)\n'
        r'    (?:target_link_libraries|target_compile_options|target_include_directories|set_target_properties|if\(MSVC\)|message\(STATUS).*?\n'
        r'    set_target_properties\([^\)]*\)\n'
        r'(?:    message\(STATUS [^\)]*\)\n)?'
        r'^endif\(\)',
        re.MULTILINE | re.DOTALL,
    )
    def repl(m, cpp=cpp_rel):
        return m.group(1) + 'if(0)  # [RAWRXD_BUILD_SOURCE_INTEGRITY_001] Missing: ' + cpp + '\n' + m.group(3) + 'endif()\n'
    content = pattern.sub(repl, content)

with open(CMAKE, "w", encoding="utf-8") as f:
    f.write(content)

print("Done")
