option casemap:none

ENT_OK                      equ 0
ENT_E_INVALID               equ 1
ENT_E_PRODUCT               equ 2
ENT_E_INTEGRITY             equ 3
ENT_E_CONFIG                equ 4
ENT_E_SESSION               equ 5
ENT_E_QUOTA                 equ 6
ENT_E_FAULT                 equ 7
ENT_E_RECOVERY              equ 8
ENT_E_AUDIT                 equ 9
ENT_E_TELEMETRY             equ 10
ENT_E_TRUST                 equ 11
ENT_E_COMPAT                equ 12
ENT_E_ROLLBACK              equ 13
ENT_E_SOAK                  equ 14
ENT_E_RELEASE               equ 15

ENT_BOOL_FALSE              equ 0
ENT_BOOL_TRUE               equ 1

; All fields are runtime-observed inputs. This overlay does not mint product authority.
EnterpriseObserved STRUCT
    ; prerequisite product truth
    product_binary_loaded            QWORD ?
    product_entry_reached            QWORD ?
    real_model_bytes_observed        QWORD ?
    real_tensor_math_observed        QWORD ?
    real_logits_observed             QWORD ?
    token_commit_observed            QWORD ?
    decode_commit_observed           QWORD ?
    product_runtime_rc               QWORD ?

    ; 01 build identity
    build_id_present                 QWORD ?
    source_revision_present          QWORD ?
    binary_revision_match            QWORD ?

    ; 02 artifact integrity
    artifact_hash_verified           QWORD ?
    manifest_hash_verified           QWORD ?
    tamper_count                     QWORD ?

    ; 03 config seal
    config_schema_valid              QWORD ?
    config_unknown_key_count         QWORD ?
    config_mutation_after_start      QWORD ?

    ; 04 capability/compat matrix
    cpu_supported                    QWORD ?
    os_supported                     QWORD ?
    gpu_path_supported               QWORD ?
    model_format_supported           QWORD ?
    codec_supported                  QWORD ?

    ; 05 model trust validation
    parser_bounds_faults             QWORD ?
    invalid_shard_faults             QWORD ?
    metadata_overflow_faults         QWORD ?
    untrusted_path_escape_faults     QWORD ?

    ; 06 session isolation
    active_sessions                  QWORD ?
    cross_session_state_faults       QWORD ?
    cross_session_kv_faults          QWORD ?
    cancelled_session_leaks          QWORD ?

    ; 07 quotas/budgets
    host_budget_violations           QWORD ?
    gpu_budget_violations            QWORD ?
    kv_budget_violations             QWORD ?
    file_handle_leaks                QWORD ?

    ; 08 fault containment
    fatal_process_corruption         QWORD ?
    double_free_faults               QWORD ?
    use_after_free_faults            QWORD ?
    stale_generation_faults          QWORD ?

    ; 09 recovery
    recovery_attempts                QWORD ?
    recovery_successes               QWORD ?
    unrecovered_faults               QWORD ?
    reusable_after_recovery          QWORD ?

    ; 10 audit journal
    audit_events                     QWORD ?
    audit_sequence_gaps              QWORD ?
    audit_duplicate_ids              QWORD ?
    audit_unattributed_events        QWORD ?

    ; 11 telemetry reconciliation
    telemetry_events                 QWORD ?
    telemetry_counter_mismatches     QWORD ?
    telemetry_dropped_critical       QWORD ?

    ; 12 deterministic shutdown/restart
    clean_shutdowns                  QWORD ?
    dirty_shutdowns                  QWORD ?
    restart_passes                   QWORD ?
    restart_state_corruption         QWORD ?

    ; 13 rollback
    rollback_image_present           QWORD ?
    rollback_attempts                QWORD ?
    rollback_successes               QWORD ?
    rollback_data_loss_faults        QWORD ?

    ; 14 soak/chaos
    soak_minutes                     QWORD ?
    soak_required_minutes            QWORD ?
    chaos_cases_executed             QWORD ?
    chaos_cases_required             QWORD ?
    chaos_uncontained_faults         QWORD ?

    ; 15 release aggregation
    clean_machine_build_pass         QWORD ?
    clean_machine_run_pass           QWORD ?
    upgrade_path_pass                QWORD ?
    downgrade_path_pass              QWORD ?
    packaging_pass                   QWORD ?
    version_surface_pass             QWORD ?
EnterpriseObserved ENDS

EnterpriseGateResult STRUCT
    product_prereq_pass              QWORD ?
    gate01_build_identity            QWORD ?
    gate02_integrity                 QWORD ?
    gate03_config                    QWORD ?
    gate04_compat                    QWORD ?
    gate05_model_trust               QWORD ?
    gate06_session_isolation         QWORD ?
    gate07_quotas                    QWORD ?
    gate08_fault_containment         QWORD ?
    gate09_recovery                  QWORD ?
    gate10_audit                     QWORD ?
    gate11_telemetry                 QWORD ?
    gate12_restart                   QWORD ?
    gate13_rollback                  QWORD ?
    gate14_soak_chaos                QWORD ?
    gate15_release                   QWORD ?
    enterprise_ready                 QWORD ?
    first_fail_code                  QWORD ?
EnterpriseGateResult ENDS

ent_evaluate_all PROTO
