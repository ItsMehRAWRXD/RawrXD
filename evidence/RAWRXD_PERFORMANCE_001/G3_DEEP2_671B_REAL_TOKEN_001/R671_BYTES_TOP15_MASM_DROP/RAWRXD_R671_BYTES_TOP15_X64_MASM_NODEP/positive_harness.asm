option casemap:none
include r671_bytes15.inc
ExitProcess PROTO

.data?
raw    R671BytesRaw <>
result R671BytesResult <>

.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog

    mov raw.generation_id, 55
    mov raw.lease_generation_id, 55
    mov rax, 412316860416
    mov raw.file_bytes, rax
    mov rax, 68719476736
    mov raw.file_offset, rax
    mov raw.requested_bytes, 16
    mov raw.lease_active, 1
    mov raw.lease_request_offset, rax
    mov raw.lease_bytes, 16
    mov rax, 0000000100011000h
    mov raw.lease_ptr, rax
    mov rax, 0000000100010000h
    mov raw.lease_view_base, rax
    mov raw.lease_delta, 1000h
    mov raw.lease_view_bytes, 10010h
    mov rax, 268435456
    mov raw.configured_mapped_bound, rax
    mov raw.mapped_bytes_live, 10010h
    mov raw.primitive_bytes_consumed, 16
    mov raw.acquire_count, 1
    mov raw.checksum_u64, 12345678h
    mov raw.checksum_observed, 1
    mov raw.release_count, 1
    mov raw.run_observed, 1

    lea rcx, raw
    lea rdx, result
    call R671BytesEvaluate

    cmp result.bytes_authorized, 1
    jne bad
    cmp result.pass_count, 14
    jne bad
    cmp result.fail_count, 0
    jne bad
    cmp result.notrun_count, 0
    jne bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 1
    call ExitProcess
main ENDP
END
