option casemap:none
include authoritative_token.inc

ExitProcess PROTO
GetStdHandle PROTO
WriteFile PROTO

.data?
raw     RawTokenRuntime <>
derived DerivedTokenRuntime <>
written DWORD ?
buf     BYTE 256 dup(?)

.data
msg_hdr BYTE "DUMP auth=%llu nilw=%llu bps=%llu tps=%llu bpt=%llu abpw=%llu ppm=%llu arith=%llu",0
; Use fixed lines instead of printf — no CRT.
line1 BYTE "AUTHORIZED_PASS=",0
line2 BYTE 13,10,"TOKEN_NILW_X1E9=",0
line3 BYTE 13,10,"INFO_RATE_Bps=",0
line4 BYTE 13,10,"TPS_X1000=",0
line5 BYTE 13,10,"BYTES_PER_TOKEN=",0
line6 BYTE 13,10,"ACTIVE_BPW_X1E6=",0
line7 BYTE 13,10,"PHYS_PPM=",0
line8 BYTE 13,10,"ARITH_FAULT=",0
line9 BYTE 13,10,0
digits BYTE "0123456789",0

.code
; rcx=value rdx=outbuf -> rax=bytes written
U64ToDec PROC
    push rbx
    push rsi
    push rdi
    mov rax, rcx
    mov rdi, rdx
    lea rsi, digits
    mov rbx, 10
    ; build reversed on stack
    xor ecx, ecx
    test rax, rax
    jnz td_loop
    mov byte ptr [rdi], '0'
    mov eax, 1
    jmp td_done
td_loop:
    xor edx, edx
    div rbx
    push rdx
    inc ecx
    test rax, rax
    jnz td_loop
    mov ebx, ecx
td_emit:
    pop rax
    mov al, [rsi+rax]
    mov [rdi], al
    inc rdi
    dec ecx
    jnz td_emit
    mov eax, ebx
td_done:
    pop rdi
    pop rsi
    pop rbx
    ret
U64ToDec ENDP

EmitStr PROC
    ; rcx=handle rdx=ptr r8=len
    sub rsp, 40
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    add rsp, 40
    ret
EmitStr ENDP

EmitU64 PROC
    ; rcx=handle rdx=value
    push rbx
    sub rsp, 32
    mov rbx, rcx
    mov rcx, rdx
    lea rdx, buf
    call U64ToDec
    mov r8, rax
    mov rcx, rbx
    lea rdx, buf
    call EmitStr
    add rsp, 32
    pop rbx
    ret
EmitU64 ENDP

main PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov raw.form, NILW_FORM_B
    mov rax, 1000000000000
    mov raw.total_logical_weights, rax
    mov rax, 640000000000
    mov raw.active_logical_weight_visits, rax
    mov rax, 102400000000
    mov raw.new_payload_bits, rax
    mov rax, 409600000000
    mov raw.reused_bits, rax
    mov raw.reuse_events, 1000
    mov raw.generated_tokens, 128
    mov rax, 12800000000
    mov raw.wall_ns, rax
    mov raw.quality_samples, 128
    mov rax, 102400000000
    mov raw.component_bits_sum, rax
    mov raw.class_bits_sum, rax
    mov raw.payload_bits_fetched, rax
    mov raw.active_subset_samples, 128
    mov raw.overhead_samples, 128

    lea rcx, raw
    lea rdx, derived
    call AuthoritativeTokenEvaluate

    mov ecx, -11
    call GetStdHandle
    mov rbx, rax

    mov rcx, rbx
    lea rdx, line1
    mov r8, 16
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.authorized_pass
    call EmitU64

    mov rcx, rbx
    lea rdx, line2
    mov r8, 18
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.token_nilw_x1e9
    call EmitU64

    mov rcx, rbx
    lea rdx, line3
    mov r8, 16
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.information_rate_Bps
    call EmitU64

    mov rcx, rbx
    lea rdx, line4
    mov r8, 12
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.tps_x1000
    call EmitU64

    mov rcx, rbx
    lea rdx, line5
    mov r8, 18
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.new_payload_bytes_per_token
    call EmitU64

    mov rcx, rbx
    lea rdx, line6
    mov r8, 18
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.active_bpw_x1e6
    call EmitU64

    mov rcx, rbx
    lea rdx, line7
    mov r8, 11
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.physicalization_ppm
    call EmitU64

    mov rcx, rbx
    lea rdx, line8
    mov r8, 14
    call EmitStr
    mov rcx, rbx
    mov rdx, derived.arithmetic_fault
    call EmitU64

    mov rcx, rbx
    lea rdx, line9
    mov r8, 2
    call EmitStr

    cmp derived.authorized_pass, 1
    jne bad
    cmp derived.token_nilw_x1e9, 800000
    jne bad
    cmp derived.information_rate_Bps, 1000000000
    jne bad
    cmp derived.tps_x1000, 10000
    jne bad
    mov rax, 100000000
    cmp derived.new_payload_bytes_per_token, rax
    jne bad
    cmp derived.active_bpw_x1e6, 160000
    jne bad
    cmp derived.physicalization_ppm, 5000
    jne bad

    xor ecx, ecx
    call ExitProcess
bad:
    mov ecx, 2
    call ExitProcess
main ENDP
END
