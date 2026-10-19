from pathlib import Path
R=Path(__file__).resolve().parent
core_names=["usr_core.asm","usr_residency.asm","usr_alias_budget.asm","usr_hot.asm","usr_batch_receipt.asm"]
core="\n".join((R/n).read_text(errors="ignore").lower() for n in core_names)
all_text="\n".join(p.read_text(errors="ignore") for p in R.iterdir() if p.is_file())

symbols=[
"usr_switch_model","usr_validate_current","USR_REQ_DYNAMIC_OBSERVED",
"usr_dynamic_observed","lock cmpxchg","usr_join_wait","usr_fail_mg",
"usr_evict","usr_alias_acquire","usr_host_reserve","usr_gpu_reserve",
"usr_hot_identity","duplicate_gpu_uploads","usr_batch_validate","usr_receipt_region"
]
checks={s:(s in all_text) for s in symbols}
forbidden=["deepseek","kimi","qwen","llama","mistral","expert_count","top_k","mla"]
checks["family_free_core"]=all(x not in core for x in forbidden)
provider=(R/"usr_provider_abi.inc").read_text(errors="ignore").lower()
checks["provider_has_no_region_pointer"]="ptr usrregion" not in provider and "usrregion struct" not in provider
checks["promote_absent_core"]="promote" not in core
checks["mg_owner_kept"]="MG_REDEFINED=0" in (R/"TOP15_ENHANCEMENTS.txt").read_text()
checks["call_alignment_residency"]="sub rsp,28h" in (R/"usr_residency.asm").read_text()
checks["batch_nonvolatile_saved"]="push r12" in (R/"usr_batch_receipt.asm").read_text()

print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
