from pathlib import Path
R=Path(__file__).resolve().parent
src="\n".join(p.read_text(errors="ignore") for p in R.glob("*") if p.suffix in {".asm",".inc"})
provider=(R/"ss_real_provider.asm").read_text()
scan=(R/"ss_gguf_scan.asm").read_text()
phase=(R/"ss_product_phase.asm").read_text()
residency="\n".join((R/n).read_text(errors="ignore") for n in [
    "usr_core.asm","usr_residency.asm","usr_alias_budget.asm","usr_hot.asm","usr_batch_receipt.asm"
]).lower()

checks={
 "real_file_open":"CreateFileA" in provider and "GetFileSizeEx" in provider,
 "real_exact_seek_read":"SetFilePointerEx" in provider and "ReadFile" in provider,
 "large_read_chunking":"40000000h" in provider,
 "real_mem_provider":"rep movsb" in provider,
 "concrete_provider_dispatch":"SS_PROVIDER_FILE" in provider and "SS_PROVIDER_MEM" in provider,
 "gguf_magic":"GGUF_MAGIC" in scan and "46554747h" in scan,
 "metadata_skip":"gg_skip_value PROC" in scan,
 "general_alignment":"general.alignment" in scan,
 "two_pass_tensor_scan":"ggf_t1_loop" in scan and "ggf_t2_loop" in scan,
 "next_offset_extent":"next rel" in scan or "0FFFFFFFFFFFFFFFFh" in scan,
 "anchor_adapter":"token_embd.weight" in (R/"ss_anchor_adapter.asm").read_text() and "output.weight" in (R/"ss_anchor_adapter.asm").read_text(),
 "host_real_alloc":"VirtualAlloc" in phase and "VirtualFree" in phase,
 "provider_real_read_in_phase":"ss_file_read_exact" in phase,
 "residency_commits_warm":"usr_commit_warm" in phase,
 "backend_materializes_only":"promote_fn" in phase and "usr_hot_commit" in phase,
 "hot_after_backend_proof":"readback_parity" in phase and "usr_hot_commit" in phase,
 "explicit_interop_failure":"SS_E_DEEP2_INTEROP" in phase,
 "token_not_run":"SS_TOKEN_COMMIT_NOT_RUN" in phase,
 "deep2_not_run":"SS_DEEP2_CONSUME_NOT_RUN" in phase,
 "no_family_names_in_residency":all(x not in residency for x in ["deepseek","kimi","qwen","llama","mistral"]),
 "mg_not_redefined":"MG_REDEFINED=0" in (R/"PRODUCT_BIND_BOUNDARY.txt").read_text(),
 "no_todo_tokens":all(x not in src.lower() for x in ["todo","placeholder"]),
}
print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
