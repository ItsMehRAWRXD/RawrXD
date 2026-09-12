option casemap:none
include enterprise_gate.inc
ExitProcess PROTO :DWORD
.data
obs EnterpriseObserved <>
res EnterpriseGateResult <>
.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    mov obs.product_binary_loaded,1
    mov obs.product_entry_reached,1
    mov obs.real_model_bytes_observed,1
    mov obs.real_tensor_math_observed,1
    mov obs.real_logits_observed,1
    mov obs.token_commit_observed,1
    mov obs.decode_commit_observed,1
    mov obs.build_id_present,1
    mov obs.source_revision_present,1
    mov obs.binary_revision_match,1
    mov obs.artifact_hash_verified,1
    mov obs.manifest_hash_verified,1
    mov obs.config_schema_valid,1
    mov obs.cpu_supported,1
    mov obs.os_supported,1
    mov obs.gpu_path_supported,1
    mov obs.model_format_supported,1
    mov obs.codec_supported,1
    mov obs.active_sessions,2
    mov obs.recovery_attempts,2
    mov obs.recovery_successes,2
    mov obs.reusable_after_recovery,1
    mov obs.audit_events,100
    mov obs.telemetry_events,100
    mov obs.clean_shutdowns,2
    mov obs.restart_passes,2
    mov obs.rollback_image_present,1
    mov obs.rollback_attempts,1
    mov obs.rollback_successes,1
    mov obs.soak_minutes,120
    mov obs.soak_required_minutes,120
    mov obs.chaos_cases_executed,10
    mov obs.chaos_cases_required,10
    mov obs.clean_machine_build_pass,1
    mov obs.clean_machine_run_pass,1
    mov obs.upgrade_path_pass,1
    mov obs.downgrade_path_pass,1
    mov obs.packaging_pass,1
    mov obs.version_surface_pass,1
    lea rcx,obs
    lea rdx,res
    call ent_evaluate_all
    test eax,eax
    jnz bad
    cmp res.product_prereq_pass,1
    jne bad
    cmp res.enterprise_ready,1
    jne bad
    xor ecx,ecx
    call ExitProcess
bad:
    mov ecx,1
    call ExitProcess
main ENDP
END
