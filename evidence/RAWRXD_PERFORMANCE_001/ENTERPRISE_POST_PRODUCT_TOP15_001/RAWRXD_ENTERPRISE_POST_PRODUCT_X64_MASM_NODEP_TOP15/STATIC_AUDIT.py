from pathlib import Path
R=Path(__file__).resolve().parent
inc=(R/"enterprise_gate.inc").read_text()
asm=(R/"enterprise_gate.asm").read_text()
doc=(R/"ENTERPRISE_TOP15.txt").read_text()
checks={
 "15_gate_fields": all(f"gate{i:02d}_" in inc for i in range(1,16)),
 "product_prereq":"product_prereq PROC" in asm,
 "requires_real_model":"real_model_bytes_observed" in inc,
 "requires_real_math":"real_tensor_math_observed" in inc,
 "requires_logits":"real_logits_observed" in inc,
 "requires_token_commit":"token_commit_observed" in inc,
 "requires_decode_commit":"decode_commit_observed" in inc,
 "integrity_gate":"gate02 PROC" in asm and "tamper_count" in asm,
 "config_gate":"gate03 PROC" in asm and "config_unknown_key_count" in asm,
 "trust_gate":"gate05 PROC" in asm and "metadata_overflow_faults" in asm,
 "session_gate":"gate06 PROC" in asm and "cross_session_kv_faults" in asm,
 "quota_gate":"gate07 PROC" in asm and "gpu_budget_violations" in asm,
 "fault_gate":"gate08 PROC" in asm and "use_after_free_faults" in asm,
 "recovery_gate":"gate09 PROC" in asm and "reusable_after_recovery" in asm,
 "audit_gate":"gate10 PROC" in asm and "audit_sequence_gaps" in asm,
 "telemetry_gate":"gate11 PROC" in asm and "telemetry_counter_mismatches" in asm,
 "restart_gate":"gate12 PROC" in asm and "restart_passes" in asm,
 "rollback_gate":"gate13 PROC" in asm and "rollback_successes" in asm,
 "soak_gate":"gate14 PROC" in asm and "chaos_uncontained_faults" in asm,
 "release_gate":"gate15 PROC" in asm and "clean_machine_run_pass" in asm,
 "enterprise_aggregate":"enterprise_ready" in asm,
 "no_product_authority_mint":"PRODUCT_AUTHORITY_MINTED=0" in (R/"build_masm.bat").read_text(),
 "no_promote_authority_mint":"PROMOTE_AUTHORITY_MINTED=0" in (R/"build_masm.bat").read_text(),
 "no_family_specific_logic":all(x not in asm.lower() for x in ["deepseek","kimi","qwen","llama","mistral"]),
}
print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
