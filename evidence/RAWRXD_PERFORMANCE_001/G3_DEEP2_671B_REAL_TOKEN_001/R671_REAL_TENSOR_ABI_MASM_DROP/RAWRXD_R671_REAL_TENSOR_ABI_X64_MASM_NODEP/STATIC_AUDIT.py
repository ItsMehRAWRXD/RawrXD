from pathlib import Path
ROOT=Path(__file__).resolve().parent
core=(ROOT/"r671_core.asm").read_text()
prim=(ROOT/"deep2_r671_primitive.asm").read_text()
inc=(ROOT/"r671_abi.inc").read_text()
gate=(ROOT/"real_tensor_gate.asm").read_text()
h=(ROOT/"r671_abi.h").read_text()

checks={
 "open_export":"r671_open PROC" in core,
 "acquire_export":"r671_tensor_acquire PROC" in core,
 "release_export":"r671_release PROC" in core,
 "close_export":"r671_close PROC" in core,
 "primitive_export":"Deep2R671TensorPrimitive PROC" in prim,
 "lease_ptr_operand":"R671Lease.ptr" in prim,
 "map_view":"MapViewOfFile" in core,
 "unmap_view":"UnmapViewOfFile" in core,
 "range_overflow_guard":"jc ra_fail_range" in core,
 "failed_acquire_counter":"failed_acquires" in core,
 "mapped_peak_counter":"mapped_bytes_peak" in core,
 "newly_mapped_counter":"newly_mapped_bytes" in core,
 "quantized_not_faked":"dp_non_f32" in prim and "R671_E_INVALID" in prim,
 "f32_nonfinite_guard":"7F800000h" in prim,
 "canonical_header":"r671_tensor_acquire(" in h and "Deep2R671TensorPrimitive(" in h,
 "real_gate_exact_one":"generated_tokens,1" in gate and "token_commit_count,1" in gate and "decode_commit_count,1" in gate,
 "promote_absent":"PROMOTE" not in core+prim+gate,
}
print("STATIC_AUDIT=",checks)
print("STATIC_AUDIT_RESULT=" + ("PASS" if all(checks.values()) else "FAIL"))
raise SystemExit(0 if all(checks.values()) else 1)
