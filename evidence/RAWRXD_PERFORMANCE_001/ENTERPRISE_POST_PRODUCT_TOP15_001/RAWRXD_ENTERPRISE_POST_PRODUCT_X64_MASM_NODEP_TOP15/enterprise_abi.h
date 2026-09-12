/* enterprise_abi.h — C layout matching enterprise_gate.inc (no mint) */
#ifndef ENTERPRISE_ABI_H
#define ENTERPRISE_ABI_H
#include <stdint.h>
typedef struct {
    uint64_t product_binary_loaded, product_entry_reached;
    uint64_t real_model_bytes_observed, real_tensor_math_observed;
    uint64_t real_logits_observed, token_commit_observed;
    uint64_t decode_commit_observed, product_runtime_rc;
    uint64_t build_id_present, source_revision_present, binary_revision_match;
    uint64_t artifact_hash_verified, manifest_hash_verified, tamper_count;
    uint64_t config_schema_valid, config_unknown_key_count, config_mutation_after_start;
    uint64_t cpu_supported, os_supported, gpu_path_supported;
    uint64_t model_format_supported, codec_supported;
    uint64_t parser_bounds_faults, invalid_shard_faults;
    uint64_t metadata_overflow_faults, untrusted_path_escape_faults;
    uint64_t active_sessions, cross_session_state_faults;
    uint64_t cross_session_kv_faults, cancelled_session_leaks;
    uint64_t host_budget_violations, gpu_budget_violations;
    uint64_t kv_budget_violations, file_handle_leaks;
    uint64_t fatal_process_corruption, double_free_faults;
    uint64_t use_after_free_faults, stale_generation_faults;
    uint64_t recovery_attempts, recovery_successes, unrecovered_faults, reusable_after_recovery;
    uint64_t audit_events, audit_sequence_gaps, audit_duplicate_ids, audit_unattributed_events;
    uint64_t telemetry_events, telemetry_counter_mismatches, telemetry_dropped_critical;
    uint64_t clean_shutdowns, dirty_shutdowns, restart_passes, restart_state_corruption;
    uint64_t rollback_image_present, rollback_attempts, rollback_successes, rollback_data_loss_faults;
    uint64_t soak_minutes, soak_required_minutes, chaos_cases_executed;
    uint64_t chaos_cases_required, chaos_uncontained_faults;
    uint64_t clean_machine_build_pass, clean_machine_run_pass, upgrade_path_pass;
    uint64_t downgrade_path_pass, packaging_pass, version_surface_pass;
} EnterpriseObserved;
typedef struct {
    uint64_t product_prereq_pass, gate01_build_identity, gate02_integrity, gate03_config;
    uint64_t gate04_compat, gate05_model_trust, gate06_session_isolation, gate07_quotas;
    uint64_t gate08_fault_containment, gate09_recovery, gate10_audit, gate11_telemetry;
    uint64_t gate12_restart, gate13_rollback, gate14_soak_chaos, gate15_release;
    uint64_t enterprise_ready, first_fail_code;
} EnterpriseGateResult;
#ifdef __cplusplus
extern "C" {
#endif
int ent_evaluate_all(EnterpriseObserved *obs, EnterpriseGateResult *out);
int ent_print_split_stream(uint64_t bytes_ok, uint64_t phase_rc, uint64_t math_ok);
#ifdef __cplusplus
}
#endif
#endif
