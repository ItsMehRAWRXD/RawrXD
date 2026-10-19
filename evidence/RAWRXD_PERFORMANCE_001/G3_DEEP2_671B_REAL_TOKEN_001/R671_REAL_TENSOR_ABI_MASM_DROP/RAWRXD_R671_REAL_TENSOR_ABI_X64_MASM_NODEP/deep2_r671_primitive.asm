option casemap:none
include r671_abi.inc

.code

; Concrete leased-tensor primitive.
; tensor_type 0 == F32 only.
; It always computes a checksum over exactly desc.byte_length bytes,
; proving lease.ptr is the operand source.
; It computes a scalar F32 sum only when descriptor is exact F32.
Deep2R671TensorPrimitive PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,20h
    .allocstack 20h
    .endprolog

    mov rsi,rcx        ; lease
    mov rbx,rdx        ; desc
    mov rdi,r8         ; out
    test rsi,rsi
    jz dp_invalid
    test rbx,rbx
    jz dp_invalid
    test rdi,rdi
    jz dp_invalid
    cmp [rsi].R671Lease.active,1
    jne dp_state
    mov rax,[rsi].R671Lease.data_ptr
    test rax,rax
    jz dp_state

    ; Descriptor must point at the exact acquired region.
    mov rcx,[rbx].R671TensorDesc.file_offset
    cmp rcx,[rsi].R671Lease.request_offset
    jne dp_range
    mov rcx,[rbx].R671TensorDesc.byte_length
    test rcx,rcx
    jz dp_range
    cmp rcx,[rsi].R671Lease.bytes
    ja dp_range

    ; clear result
    xor eax,eax
    mov rcx,SIZEOF R671PrimitiveResult
    mov rdx,rdi
dp_zero:
    test rcx,rcx
    jz dp_checksum_start
    mov byte ptr [rdx],al
    inc rdx
    dec rcx
    jmp dp_zero

dp_checksum_start:
    mov rdx,[rsi].R671Lease.data_ptr
    mov rcx,[rbx].R671TensorDesc.byte_length
    mov r8,14695981039346656037
    mov r10,1099511628211
dp_checksum:
    test rcx,rcx
    jz dp_type
    movzx eax,byte ptr [rdx]
    xor r8,rax
    imul r8,r10
    inc rdx
    dec rcx
    jmp dp_checksum
dp_type:
    mov [rdi].R671PrimitiveResult.checksum_u64,r8

    cmp [rbx].R671TensorDesc.tensor_type,0
    jne dp_non_f32
    cmp [rbx].R671TensorDesc.element_bytes,4
    jne dp_non_f32

    mov rax,[rbx].R671TensorDesc.element_count
    mov rcx,rax
    shl rax,2
    cmp rax,[rbx].R671TensorDesc.byte_length
    jne dp_range_after_zero

    pxor xmm0,xmm0
    mov rdx,[rsi].R671Lease.data_ptr
    xor r9,r9
dp_f32_loop:
    cmp r9,rcx
    jae dp_f32_done
    movss xmm1,dword ptr [rdx+r9*4]

    ; finite iff exponent != 0xFF
    mov eax,dword ptr [rdx+r9*4]
    and eax,7F800000h
    cmp eax,7F800000h
    je dp_nonfinite

    addss xmm0,xmm1
    inc r9
    jmp dp_f32_loop

dp_nonfinite:
    inc qword ptr [rdi].R671PrimitiveResult.nonfinite_count
    inc r9
    jmp dp_f32_loop

dp_f32_done:
    mov [rdi].R671PrimitiveResult.elements_consumed,rcx
    movd eax,xmm0
    mov [rdi].R671PrimitiveResult.scalar_f32_bits,eax
    cmp [rdi].R671PrimitiveResult.nonfinite_count,0
    jne dp_nonfinite_status
    mov dword ptr [rdi].R671PrimitiveResult.status,R671_OK
    xor eax,eax
    jmp dp_done

dp_nonfinite_status:
    mov dword ptr [rdi].R671PrimitiveResult.status,R671_E_INVALID
    mov eax,R671_E_INVALID
    jmp dp_done

dp_non_f32:
    mov dword ptr [rdi].R671PrimitiveResult.status,R671_E_INVALID
    mov eax,R671_E_INVALID
    jmp dp_done

dp_range_after_zero:
    mov dword ptr [rdi].R671PrimitiveResult.status,R671_E_RANGE
    mov eax,R671_E_RANGE
    jmp dp_done
dp_range:
    mov eax,R671_E_RANGE
    jmp dp_done
dp_state:
    mov eax,R671_E_STATE
    jmp dp_done
dp_invalid:
    mov eax,R671_E_INVALID
dp_done:
    add rsp,20h
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2R671TensorPrimitive ENDP

END
