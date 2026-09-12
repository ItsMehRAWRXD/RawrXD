option casemap:none
include enterprise_gate.inc

.code

zero_result PROC
    ; rcx=result
    xor eax,eax
    mov rdx,SIZEOF EnterpriseGateResult
zr_loop:
    test rdx,rdx
    jz zr_done
    mov byte ptr [rcx],al
    inc rcx
    dec rdx
    jmp zr_loop
zr_done:
    ret
zero_result ENDP

set_fail_once PROC
    ; rcx=result, rdx=code
    cmp qword ptr [rcx].EnterpriseGateResult.first_fail_code,0
    jne sfo_done
    mov [rcx].EnterpriseGateResult.first_fail_code,rdx
sfo_done:
    ret
set_fail_once ENDP

; 01 Build identity
gate01 PROC
    cmp [rcx].EnterpriseObserved.build_id_present,1
    jne g1_no
    cmp [rcx].EnterpriseObserved.source_revision_present,1
    jne g1_no
    cmp [rcx].EnterpriseObserved.binary_revision_match,1
    jne g1_no
    mov eax,1
    ret
g1_no:
    xor eax,eax
    ret
gate01 ENDP

; 02 Artifact integrity
gate02 PROC
    cmp [rcx].EnterpriseObserved.artifact_hash_verified,1
    jne g2_no
    cmp [rcx].EnterpriseObserved.manifest_hash_verified,1
    jne g2_no
    cmp [rcx].EnterpriseObserved.tamper_count,0
    jne g2_no
    mov eax,1
    ret
g2_no:
    xor eax,eax
    ret
gate02 ENDP

; 03 Configuration seal
gate03 PROC
    cmp [rcx].EnterpriseObserved.config_schema_valid,1
    jne g3_no
    cmp [rcx].EnterpriseObserved.config_unknown_key_count,0
    jne g3_no
    cmp [rcx].EnterpriseObserved.config_mutation_after_start,0
    jne g3_no
    mov eax,1
    ret
g3_no:
    xor eax,eax
    ret
gate03 ENDP

; 04 Compatibility
gate04 PROC
    cmp [rcx].EnterpriseObserved.cpu_supported,1
    jne g4_no
    cmp [rcx].EnterpriseObserved.os_supported,1
    jne g4_no
    cmp [rcx].EnterpriseObserved.gpu_path_supported,1
    jne g4_no
    cmp [rcx].EnterpriseObserved.model_format_supported,1
    jne g4_no
    cmp [rcx].EnterpriseObserved.codec_supported,1
    jne g4_no
    mov eax,1
    ret
g4_no:
    xor eax,eax
    ret
gate04 ENDP

; 05 Untrusted model/input validation
gate05 PROC
    cmp [rcx].EnterpriseObserved.parser_bounds_faults,0
    jne g5_no
    cmp [rcx].EnterpriseObserved.invalid_shard_faults,0
    jne g5_no
    cmp [rcx].EnterpriseObserved.metadata_overflow_faults,0
    jne g5_no
    cmp [rcx].EnterpriseObserved.untrusted_path_escape_faults,0
    jne g5_no
    mov eax,1
    ret
g5_no:
    xor eax,eax
    ret
gate05 ENDP

; 06 Session isolation
gate06 PROC
    cmp [rcx].EnterpriseObserved.cross_session_state_faults,0
    jne g6_no
    cmp [rcx].EnterpriseObserved.cross_session_kv_faults,0
    jne g6_no
    cmp [rcx].EnterpriseObserved.cancelled_session_leaks,0
    jne g6_no
    mov eax,1
    ret
g6_no:
    xor eax,eax
    ret
gate06 ENDP

; 07 Budget and leak control
gate07 PROC
    cmp [rcx].EnterpriseObserved.host_budget_violations,0
    jne g7_no
    cmp [rcx].EnterpriseObserved.gpu_budget_violations,0
    jne g7_no
    cmp [rcx].EnterpriseObserved.kv_budget_violations,0
    jne g7_no
    cmp [rcx].EnterpriseObserved.file_handle_leaks,0
    jne g7_no
    mov eax,1
    ret
g7_no:
    xor eax,eax
    ret
gate07 ENDP

; 08 Fault containment
gate08 PROC
    cmp [rcx].EnterpriseObserved.fatal_process_corruption,0
    jne g8_no
    cmp [rcx].EnterpriseObserved.double_free_faults,0
    jne g8_no
    cmp [rcx].EnterpriseObserved.use_after_free_faults,0
    jne g8_no
    cmp [rcx].EnterpriseObserved.stale_generation_faults,0
    jne g8_no
    mov eax,1
    ret
g8_no:
    xor eax,eax
    ret
gate08 ENDP

; 09 Recovery
gate09 PROC
    mov rax,[rcx].EnterpriseObserved.recovery_attempts
    cmp [rcx].EnterpriseObserved.recovery_successes,rax
    jne g9_no
    cmp [rcx].EnterpriseObserved.unrecovered_faults,0
    jne g9_no
    cmp rax,0
    je g9_yes
    cmp [rcx].EnterpriseObserved.reusable_after_recovery,1
    jne g9_no
g9_yes:
    mov eax,1
    ret
g9_no:
    xor eax,eax
    ret
gate09 ENDP

; 10 Audit journal
gate10 PROC
    cmp [rcx].EnterpriseObserved.audit_events,0
    je g10_no
    cmp [rcx].EnterpriseObserved.audit_sequence_gaps,0
    jne g10_no
    cmp [rcx].EnterpriseObserved.audit_duplicate_ids,0
    jne g10_no
    cmp [rcx].EnterpriseObserved.audit_unattributed_events,0
    jne g10_no
    mov eax,1
    ret
g10_no:
    xor eax,eax
    ret
gate10 ENDP

; 11 Telemetry reconciliation
gate11 PROC
    cmp [rcx].EnterpriseObserved.telemetry_events,0
    je g11_no
    cmp [rcx].EnterpriseObserved.telemetry_counter_mismatches,0
    jne g11_no
    cmp [rcx].EnterpriseObserved.telemetry_dropped_critical,0
    jne g11_no
    mov eax,1
    ret
g11_no:
    xor eax,eax
    ret
gate11 ENDP

; 12 Clean restart
gate12 PROC
    cmp [rcx].EnterpriseObserved.dirty_shutdowns,0
    jne g12_no
    cmp [rcx].EnterpriseObserved.restart_state_corruption,0
    jne g12_no
    cmp [rcx].EnterpriseObserved.restart_passes,0
    je g12_no
    mov eax,1
    ret
g12_no:
    xor eax,eax
    ret
gate12 ENDP

; 13 Rollback
gate13 PROC
    cmp [rcx].EnterpriseObserved.rollback_image_present,1
    jne g13_no
    mov rax,[rcx].EnterpriseObserved.rollback_attempts
    cmp [rcx].EnterpriseObserved.rollback_successes,rax
    jne g13_no
    cmp [rcx].EnterpriseObserved.rollback_data_loss_faults,0
    jne g13_no
    mov eax,1
    ret
g13_no:
    xor eax,eax
    ret
gate13 ENDP

; 14 Soak/chaos
gate14 PROC
    mov rax,[rcx].EnterpriseObserved.soak_minutes
    cmp rax,[rcx].EnterpriseObserved.soak_required_minutes
    jb g14_no
    mov rax,[rcx].EnterpriseObserved.chaos_cases_executed
    cmp rax,[rcx].EnterpriseObserved.chaos_cases_required
    jb g14_no
    cmp [rcx].EnterpriseObserved.chaos_uncontained_faults,0
    jne g14_no
    mov eax,1
    ret
g14_no:
    xor eax,eax
    ret
gate14 ENDP

; 15 Release/install/upgrade
gate15 PROC
    cmp [rcx].EnterpriseObserved.clean_machine_build_pass,1
    jne g15_no
    cmp [rcx].EnterpriseObserved.clean_machine_run_pass,1
    jne g15_no
    cmp [rcx].EnterpriseObserved.upgrade_path_pass,1
    jne g15_no
    cmp [rcx].EnterpriseObserved.downgrade_path_pass,1
    jne g15_no
    cmp [rcx].EnterpriseObserved.packaging_pass,1
    jne g15_no
    cmp [rcx].EnterpriseObserved.version_surface_pass,1
    jne g15_no
    mov eax,1
    ret
g15_no:
    xor eax,eax
    ret
gate15 ENDP

product_prereq PROC
    cmp [rcx].EnterpriseObserved.product_binary_loaded,1
    jne p_no
    cmp [rcx].EnterpriseObserved.product_entry_reached,1
    jne p_no
    cmp [rcx].EnterpriseObserved.real_model_bytes_observed,1
    jne p_no
    cmp [rcx].EnterpriseObserved.real_tensor_math_observed,1
    jne p_no
    cmp [rcx].EnterpriseObserved.real_logits_observed,1
    jne p_no
    cmp [rcx].EnterpriseObserved.token_commit_observed,1
    jne p_no
    cmp [rcx].EnterpriseObserved.decode_commit_observed,1
    jne p_no
    cmp [rcx].EnterpriseObserved.product_runtime_rc,0
    jne p_no
    mov eax,1
    ret
p_no:
    xor eax,eax
    ret
product_prereq ENDP

ent_evaluate_all PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,20h
    .allocstack 20h
    .endprolog

    mov rsi,rcx
    mov rdi,rdx
    test rsi,rsi
    jz ee_bad
    test rdi,rdi
    jz ee_bad

    mov rcx,rdi
    call zero_result

    mov rcx,rsi
    call product_prereq
    mov [rdi].EnterpriseGateResult.product_prereq_pass,rax
    test eax,eax
    jnz ee_g1
    mov rcx,rdi
    mov edx,ENT_E_PRODUCT
    call set_fail_once
    mov eax,ENT_E_PRODUCT
    jmp ee_done

ee_g1:
    mov rcx,rsi
    call gate01
    mov [rdi].EnterpriseGateResult.gate01_build_identity,rax
    test eax,eax
    jnz ee_g2
    mov rcx,rdi
    mov edx,ENT_E_INTEGRITY
    call set_fail_once
ee_g2:
    mov rcx,rsi
    call gate02
    mov [rdi].EnterpriseGateResult.gate02_integrity,rax
    test eax,eax
    jnz ee_g3
    mov rcx,rdi
    mov edx,ENT_E_INTEGRITY
    call set_fail_once
ee_g3:
    mov rcx,rsi
    call gate03
    mov [rdi].EnterpriseGateResult.gate03_config,rax
    test eax,eax
    jnz ee_g4
    mov rcx,rdi
    mov edx,ENT_E_CONFIG
    call set_fail_once
ee_g4:
    mov rcx,rsi
    call gate04
    mov [rdi].EnterpriseGateResult.gate04_compat,rax
    test eax,eax
    jnz ee_g5
    mov rcx,rdi
    mov edx,ENT_E_COMPAT
    call set_fail_once
ee_g5:
    mov rcx,rsi
    call gate05
    mov [rdi].EnterpriseGateResult.gate05_model_trust,rax
    test eax,eax
    jnz ee_g6
    mov rcx,rdi
    mov edx,ENT_E_TRUST
    call set_fail_once
ee_g6:
    mov rcx,rsi
    call gate06
    mov [rdi].EnterpriseGateResult.gate06_session_isolation,rax
    test eax,eax
    jnz ee_g7
    mov rcx,rdi
    mov edx,ENT_E_SESSION
    call set_fail_once
ee_g7:
    mov rcx,rsi
    call gate07
    mov [rdi].EnterpriseGateResult.gate07_quotas,rax
    test eax,eax
    jnz ee_g8
    mov rcx,rdi
    mov edx,ENT_E_QUOTA
    call set_fail_once
ee_g8:
    mov rcx,rsi
    call gate08
    mov [rdi].EnterpriseGateResult.gate08_fault_containment,rax
    test eax,eax
    jnz ee_g9
    mov rcx,rdi
    mov edx,ENT_E_FAULT
    call set_fail_once
ee_g9:
    mov rcx,rsi
    call gate09
    mov [rdi].EnterpriseGateResult.gate09_recovery,rax
    test eax,eax
    jnz ee_g10
    mov rcx,rdi
    mov edx,ENT_E_RECOVERY
    call set_fail_once
ee_g10:
    mov rcx,rsi
    call gate10
    mov [rdi].EnterpriseGateResult.gate10_audit,rax
    test eax,eax
    jnz ee_g11
    mov rcx,rdi
    mov edx,ENT_E_AUDIT
    call set_fail_once
ee_g11:
    mov rcx,rsi
    call gate11
    mov [rdi].EnterpriseGateResult.gate11_telemetry,rax
    test eax,eax
    jnz ee_g12
    mov rcx,rdi
    mov edx,ENT_E_TELEMETRY
    call set_fail_once
ee_g12:
    mov rcx,rsi
    call gate12
    mov [rdi].EnterpriseGateResult.gate12_restart,rax
    test eax,eax
    jnz ee_g13
    mov rcx,rdi
    mov edx,ENT_E_RELEASE
    call set_fail_once
ee_g13:
    mov rcx,rsi
    call gate13
    mov [rdi].EnterpriseGateResult.gate13_rollback,rax
    test eax,eax
    jnz ee_g14
    mov rcx,rdi
    mov edx,ENT_E_ROLLBACK
    call set_fail_once
ee_g14:
    mov rcx,rsi
    call gate14
    mov [rdi].EnterpriseGateResult.gate14_soak_chaos,rax
    test eax,eax
    jnz ee_g15
    mov rcx,rdi
    mov edx,ENT_E_SOAK
    call set_fail_once
ee_g15:
    mov rcx,rsi
    call gate15
    mov [rdi].EnterpriseGateResult.gate15_release,rax
    test eax,eax
    jnz ee_aggregate
    mov rcx,rdi
    mov edx,ENT_E_RELEASE
    call set_fail_once

ee_aggregate:
    ; Aggregate explicitly to avoid any struct layout ambiguity.
    cmp [rdi].EnterpriseGateResult.gate01_build_identity,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate02_integrity,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate03_config,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate04_compat,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate05_model_trust,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate06_session_isolation,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate07_quotas,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate08_fault_containment,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate09_recovery,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate10_audit,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate11_telemetry,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate12_restart,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate13_rollback,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate14_soak_chaos,1
    jne ee_not_ready
    cmp [rdi].EnterpriseGateResult.gate15_release,1
    jne ee_not_ready

    mov qword ptr [rdi].EnterpriseGateResult.enterprise_ready,1
    xor eax,eax
    jmp ee_done

ee_not_ready:
    mov rax,[rdi].EnterpriseGateResult.first_fail_code
    test rax,rax
    jnz ee_done
    mov eax,ENT_E_RELEASE
    jmp ee_done

ee_bad:
    mov eax,ENT_E_INVALID
ee_done:
    add rsp,20h
    pop rdi
    pop rsi
    pop rbx
    ret
ent_evaluate_all ENDP

END
