from pathlib import Path

ROOT=Path(__file__).resolve().parent
inc=(ROOT/"r671_arg5_residency_hardening.inc").read_text()
asm=(ROOT/"r671_arg5_residency_hardening.asm").read_text()
patch=(ROOT/"PATCH_PATTERN.asm").read_text()

checks={
 "arg5_entry_28":"R671_ENTRY_ARG5_OFFSET        equ 28h" in inc,
 "push_delta_20":"R671_ACQUIRE_PUSH_BYTES       equ 20h" in inc,
 "local_delta_50":"R671_ACQUIRE_LOCAL_BYTES      equ 50h" in inc,
 "arg5_symbolic":"R671_ACQUIRE_ARG5_OFFSET" in inc,
 "arg5_assert_98":"NE 98h" in inc,
 "patch_uses_symbolic_arg5":"[rsp+R671_ACQUIRE_ARG5_OFFSET]" in patch,
 "generation_preserved":"mov [rsp+38h],r11" in patch and "mov r10,[rsp+38h]" in patch,
 "residency_bound_present":"configured_bound" in inc,
 "reserve_cas":"lock cmpxchg" in asm,
 "peak_cas":"mapped_bytes_peak" in asm and "rr_peak:" in asm,
 "release_underflow_fails":"rg_account:" in asm,
 "invalid_release_count":"invalid_release_count" in asm,
 "bound_reject_count":"bound_reject_count" in asm,
 "accounting_fault_count":"accounting_fault_count" in asm,
 "mapper_divergence_warning":"already locked a00eceb8..." in patch,
}
print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
