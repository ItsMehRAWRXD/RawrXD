option casemap:none
include ss_real_provider.inc

GGUF_MAGIC                  equ 46554747h
GGUF_TYPE_UINT8             equ 0
GGUF_TYPE_INT8              equ 1
GGUF_TYPE_UINT16            equ 2
GGUF_TYPE_INT16             equ 3
GGUF_TYPE_UINT32            equ 4
GGUF_TYPE_INT32             equ 5
GGUF_TYPE_FLOAT32           equ 6
GGUF_TYPE_BOOL              equ 7
GGUF_TYPE_STRING            equ 8
GGUF_TYPE_ARRAY             equ 9
GGUF_TYPE_UINT64            equ 10
GGUF_TYPE_INT64             equ 11
GGUF_TYPE_FLOAT64           equ 12

.data
general_alignment_key db "general.alignment",0

.code

; Helpers intentionally read through ss_file_read_exact; parser never maps the whole model.

gg_advance PROC
    ; rcx=file, rdx=cursor*, r8=bytes
    test rcx,rcx
    jz ga_bad
    test rdx,rdx
    jz ga_bad
    mov rax,[rdx]
    add rax,r8
    jc ga_over
    cmp rax,[rcx].SSFileCtx.file_bytes
    ja ga_range
    mov [rdx],rax
    xor eax,eax
    ret
ga_over:
    mov eax,SS_E_OVERFLOW
    ret
ga_range:
    mov eax,SS_E_RANGE
    ret
ga_bad:
    mov eax,SS_E_INVALID
    ret
gg_advance ENDP

gg_read_u32 PROC FRAME
    sub rsp,38h
    .allocstack 38h
    .endprolog
    ; rcx=file, rdx=cursor*, r8=out*
    test rcx,rcx
    jz gr32_bad
    test rdx,rdx
    jz gr32_bad
    test r8,r8
    jz gr32_bad
    mov [rsp+18h],rdx
    mov [rsp+30h],r8
    mov rdx,[rdx]
    mov r8d,4
    mov r9,[rsp+30h]
    lea rax,[rsp+28h]
    mov [rsp+20h],rax
    call ss_file_read_exact
    test eax,eax
    jnz gr32_done
    mov r11,[rsp+18h]
    add qword ptr [r11],4
gr32_done:
    add rsp,38h
    ret
gr32_bad:
    mov eax,SS_E_INVALID
    add rsp,38h
    ret
gg_read_u32 ENDP

gg_read_u64 PROC FRAME
    sub rsp,38h
    .allocstack 38h
    .endprolog
    test rcx,rcx
    jz gr64_bad
    test rdx,rdx
    jz gr64_bad
    test r8,r8
    jz gr64_bad
    mov [rsp+18h],rdx
    mov [rsp+30h],r8
    mov rdx,[rdx]
    mov r8d,8
    mov r9,[rsp+30h]
    lea rax,[rsp+28h]
    mov [rsp+20h],rax
    call ss_file_read_exact
    test eax,eax
    jnz gr64_done
    mov r11,[rsp+18h]
    add qword ptr [r11],8
gr64_done:
    add rsp,38h
    ret
gr64_bad:
    mov eax,SS_E_INVALID
    add rsp,38h
    ret
gg_read_u64 ENDP

gg_cstrlen PROC
    xor eax,eax
    test rcx,rcx
    jz gcs_done
gcs_loop:
    cmp byte ptr [rcx+rax],0
    je gcs_done
    inc rax
    cmp rax,1000h
    jb gcs_loop
    xor eax,eax
gcs_done:
    ret
gg_cstrlen ENDP

; eax=1 equal, eax=0 unequal/error
gg_file_string_equals PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,88h
    .allocstack 88h
    .endprolog
    ; rcx=file rdx=file_offset r8=len r9=cstr
    mov rbx,rcx
    mov rsi,rdx
    mov rdi,r9
    test rbx,rbx
    jz gfse_no
    test rdi,rdi
    jz gfse_no
    cmp r8,64
    ja gfse_no
    mov [rsp+78h],r8
    mov rcx,rdi
    call gg_cstrlen
    cmp rax,[rsp+78h]
    jne gfse_no
    test rax,rax
    jz gfse_no

    mov rcx,rbx
    mov rdx,rsi
    mov r8,[rsp+78h]
    lea r9,[rsp+30h]
    lea rax,[rsp+28h]
    mov [rsp+20h],rax
    call ss_file_read_exact
    test eax,eax
    jnz gfse_no

    mov rcx,[rsp+78h]
    lea rsi,[rsp+30h]
    mov rdi,rdi
    repe cmpsb
    jne gfse_no
    mov eax,1
    jmp gfse_done
gfse_no:
    xor eax,eax
gfse_done:
    add rsp,88h
    pop rdi
    pop rsi
    pop rbx
    ret
gg_file_string_equals ENDP

gg_fixed_type_size PROC
    ; ecx=type, rax=size or 0
    cmp ecx,GGUF_TYPE_UINT8
    je gfts_1
    cmp ecx,GGUF_TYPE_INT8
    je gfts_1
    cmp ecx,GGUF_TYPE_BOOL
    je gfts_1
    cmp ecx,GGUF_TYPE_UINT16
    je gfts_2
    cmp ecx,GGUF_TYPE_INT16
    je gfts_2
    cmp ecx,GGUF_TYPE_UINT32
    je gfts_4
    cmp ecx,GGUF_TYPE_INT32
    je gfts_4
    cmp ecx,GGUF_TYPE_FLOAT32
    je gfts_4
    cmp ecx,GGUF_TYPE_UINT64
    je gfts_8
    cmp ecx,GGUF_TYPE_INT64
    je gfts_8
    cmp ecx,GGUF_TYPE_FLOAT64
    je gfts_8
    xor eax,eax
    ret
gfts_1:
    mov eax,1
    ret
gfts_2:
    mov eax,2
    ret
gfts_4:
    mov eax,4
    ret
gfts_8:
    mov eax,8
    ret
gg_fixed_type_size ENDP

; rcx=file, rdx=cursor*, r8d=value_type
gg_skip_value PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,38h
    .allocstack 38h
    .endprolog
    mov rbx,rcx
    mov rsi,rdx
    mov edi,r8d
    test rbx,rbx
    jz gsv_bad
    test rsi,rsi
    jz gsv_bad

    cmp edi,GGUF_TYPE_STRING
    je gsv_string
    cmp edi,GGUF_TYPE_ARRAY
    je gsv_array

    mov ecx,edi
    call gg_fixed_type_size
    test rax,rax
    jz gsv_format
    mov rcx,rbx
    mov rdx,rsi
    mov r8,rax
    call gg_advance
    jmp gsv_done

gsv_string:
    mov rcx,rbx
    mov rdx,rsi
    lea r8,[rsp+28h]
    call gg_read_u64
    test eax,eax
    jnz gsv_done
    mov rcx,rbx
    mov rdx,rsi
    mov r8,[rsp+28h]
    call gg_advance
    jmp gsv_done

gsv_array:
    mov rcx,rbx
    mov rdx,rsi
    lea r8,[rsp+24h]
    call gg_read_u32
    test eax,eax
    jnz gsv_done
    mov rcx,rbx
    mov rdx,rsi
    lea r8,[rsp+28h]
    call gg_read_u64
    test eax,eax
    jnz gsv_done

    mov ecx,dword ptr [rsp+24h]
    cmp ecx,GGUF_TYPE_STRING
    je gsv_string_array
    cmp ecx,GGUF_TYPE_ARRAY
    je gsv_format
    call gg_fixed_type_size
    test rax,rax
    jz gsv_format
    mul qword ptr [rsp+28h]
    test rdx,rdx
    jnz gsv_overflow
    mov rcx,rbx
    mov rdx,rsi
    mov r8,rax
    call gg_advance
    jmp gsv_done

gsv_string_array:
    mov rdi,[rsp+28h]
gsv_sa_loop:
    test rdi,rdi
    jz gsv_ok
    mov rcx,rbx
    mov rdx,rsi
    lea r8,[rsp+30h]
    call gg_read_u64
    test eax,eax
    jnz gsv_done
    mov rcx,rbx
    mov rdx,rsi
    mov r8,[rsp+30h]
    call gg_advance
    test eax,eax
    jnz gsv_done
    dec rdi
    jmp gsv_sa_loop
gsv_ok:
    xor eax,eax
    jmp gsv_done
gsv_overflow:
    mov eax,SS_E_OVERFLOW
    jmp gsv_done
gsv_format:
    mov eax,SS_E_FORMAT
    jmp gsv_done
gsv_bad:
    mov eax,SS_E_INVALID
gsv_done:
    add rsp,38h
    pop rdi
    pop rsi
    pop rbx
    ret
gg_skip_value ENDP

; rcx=file, rdx=name1, r8=name2, r9=outdesc
ss_gguf_find_tensor2 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp,100h
    .allocstack 100h
    .endprolog

    mov r12,rcx
    mov r13,rdx
    mov r14,r8
    mov r15,r9
    test r12,r12
    jz ggf_bad
    test r13,r13
    jz ggf_bad
    test r14,r14
    jz ggf_bad
    test r15,r15
    jz ggf_bad

    ; zero output
    xor eax,eax
    mov rcx,SIZEOF SSTensorDesc
    mov rdx,r15
ggf_zero:
    test rcx,rcx
    jz ggf_header
    mov byte ptr [rdx],al
    inc rdx
    dec rcx
    jmp ggf_zero

ggf_header:
    mov qword ptr [rsp+40h],0        ; cursor
    mov qword ptr [rsp+48h],32       ; alignment default
    mov qword ptr [rsp+50h],0        ; priority
    mov qword ptr [rsp+58h],0        ; target rel
    mov qword ptr [rsp+60h],0        ; target elements
    mov qword ptr [rsp+0F0h],0       ; saved dim0
    mov qword ptr [rsp+0F8h],0       ; saved dim1
    mov qword ptr [rsp+68h],0FFFFFFFFFFFFFFFFh ; next rel

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+78h]
    call gg_read_u32
    test eax,eax
    jnz ggf_done
    cmp dword ptr [rsp+78h],GGUF_MAGIC
    jne ggf_format

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+7Ch]
    call gg_read_u32
    test eax,eax
    jnz ggf_done
    mov eax,dword ptr [rsp+7Ch]
    cmp eax,2
    jb ggf_format
    cmp eax,3
    ja ggf_format

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+80h]                 ; tensor count
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    cmp qword ptr [rsp+80h],10000000
    ja ggf_format

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+88h]                 ; kv count
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    cmp qword ptr [rsp+88h],1000000
    ja ggf_format

    xor ebx,ebx
ggf_kv_loop:
    cmp rbx,[rsp+88h]
    jae ggf_kv_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+90h]                 ; key len
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    mov rax,[rsp+40h]
    mov [rsp+98h],rax                ; key offset

    xor edi,edi
    cmp qword ptr [rsp+90h],17
    jne ggf_key_checked
    mov rcx,r12
    mov rdx,[rsp+98h]
    mov r8,[rsp+90h]
    lea r9,general_alignment_key
    call gg_file_string_equals
    mov edi,eax
ggf_key_checked:
    mov rcx,r12
    lea rdx,[rsp+40h]
    mov r8,[rsp+90h]
    call gg_advance
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0A0h]                ; value type
    call gg_read_u32
    test eax,eax
    jnz ggf_done

    test edi,edi
    jz ggf_skip_kv
    cmp dword ptr [rsp+0A0h],GGUF_TYPE_UINT32
    je ggf_align32
    cmp dword ptr [rsp+0A0h],GGUF_TYPE_UINT64
    je ggf_align64
    jmp ggf_skip_kv

ggf_align32:
    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0A4h]
    call gg_read_u32
    test eax,eax
    jnz ggf_done
    mov eax,dword ptr [rsp+0A4h]
    test eax,eax
    jz ggf_format
    mov [rsp+48h],rax
    jmp ggf_kv_next

ggf_align64:
    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0A8h]
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    mov rax,[rsp+0A8h]
    test rax,rax
    jz ggf_format
    mov [rsp+48h],rax
    jmp ggf_kv_next

ggf_skip_kv:
    mov rcx,r12
    lea rdx,[rsp+40h]
    mov r8d,dword ptr [rsp+0A0h]
    call gg_skip_value
    test eax,eax
    jnz ggf_done

ggf_kv_next:
    inc rbx
    jmp ggf_kv_loop

ggf_kv_done:
    mov rax,[rsp+40h]
    mov [rsp+0B0h],rax               ; tensor info start

    ; pass 1: choose preferred name1, fallback name2
    xor ebx,ebx
ggf_t1_loop:
    cmp rbx,[rsp+80h]
    jae ggf_t1_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+90h]                 ; name len
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    mov rax,[rsp+40h]
    mov [rsp+98h],rax                ; name offset

    xor edi,edi                      ; match code 0/1/2
    mov rcx,r12
    mov rdx,[rsp+98h]
    mov r8,[rsp+90h]
    mov r9,r13
    call gg_file_string_equals
    test eax,eax
    jz ggf_try_name2
    mov edi,1
    jmp ggf_name_match_done
ggf_try_name2:
    mov rcx,r12
    mov rdx,[rsp+98h]
    mov r8,[rsp+90h]
    mov r9,r14
    call gg_file_string_equals
    test eax,eax
    jz ggf_name_match_done
    mov edi,2
ggf_name_match_done:
    mov rcx,r12
    lea rdx,[rsp+40h]
    mov r8,[rsp+90h]
    call gg_advance
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0A0h]                ; n_dims
    call gg_read_u32
    test eax,eax
    jnz ggf_done
    mov eax,dword ptr [rsp+0A0h]
    test eax,eax
    jz ggf_format
    cmp eax,8
    ja ggf_format

    mov qword ptr [rsp+0B8h],1       ; element count
    mov qword ptr [rsp+0E0h],0       ; dim0
    mov qword ptr [rsp+0E8h],0       ; dim1
    xor esi,esi
ggf_dim_loop:
    cmp esi,dword ptr [rsp+0A0h]
    jae ggf_dims_done
    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0C0h]
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    cmp esi,0
    jne ggf_dim_not0
    mov rax,[rsp+0C0h]
    mov [rsp+0E0h],rax
    jmp ggf_dim_mul
ggf_dim_not0:
    cmp esi,1
    jne ggf_dim_mul
    mov rax,[rsp+0C0h]
    mov [rsp+0E8h],rax
ggf_dim_mul:
    mov rax,[rsp+0B8h]
    mul qword ptr [rsp+0C0h]
    test rdx,rdx
    jnz ggf_over
    mov [rsp+0B8h],rax
    inc esi
    jmp ggf_dim_loop
ggf_dims_done:
    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0C8h]                ; tensor type
    call gg_read_u32
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0D0h]                ; relative offset
    call gg_read_u64
    test eax,eax
    jnz ggf_done

    cmp edi,1
    jne ggf_maybe_fallback
    mov qword ptr [rsp+50h],1
    mov rax,[rsp+0D0h]
    mov [rsp+58h],rax
    mov rax,[rsp+0B8h]
    mov [rsp+60h],rax
    mov eax,dword ptr [rsp+0C8h]
    mov dword ptr [rsp+70h],eax
    mov eax,dword ptr [rsp+0A0h]
    mov dword ptr [rsp+74h],eax
    mov rax,[rsp+0E0h]
    mov [rsp+0F0h],rax
    mov rax,[rsp+0E8h]
    mov [rsp+0F8h],rax
    jmp ggf_t1_next
ggf_maybe_fallback:
    cmp edi,2
    jne ggf_t1_next
    cmp qword ptr [rsp+50h],0
    jne ggf_t1_next
    mov qword ptr [rsp+50h],2
    mov rax,[rsp+0D0h]
    mov [rsp+58h],rax
    mov rax,[rsp+0B8h]
    mov [rsp+60h],rax
    mov eax,dword ptr [rsp+0C8h]
    mov dword ptr [rsp+70h],eax
    mov eax,dword ptr [rsp+0A0h]
    mov dword ptr [rsp+74h],eax
    mov rax,[rsp+0E0h]
    mov [rsp+0F0h],rax
    mov rax,[rsp+0E8h]
    mov [rsp+0F8h],rax
ggf_t1_next:
    inc rbx
    jmp ggf_t1_loop

ggf_t1_done:
    cmp qword ptr [rsp+50h],0
    je ggf_not_found

    ; data base = align_up(end_tensor_infos, alignment)
    mov rax,[rsp+40h]
    xor rdx,rdx
    div qword ptr [rsp+48h]
    test rdx,rdx
    jz ggf_aligned
    mov rax,[rsp+40h]
    mov rcx,[rsp+48h]
    sub rcx,rdx
    add rax,rcx
    jc ggf_over
ggf_aligned:
    cmp rax,[r12].SSFileCtx.file_bytes
    ja ggf_range
    mov [rsp+0A8h],rax               ; data base

    ; pass 2: find smallest offset greater than target
    mov rax,[rsp+0B0h]
    mov [rsp+40h],rax
    xor ebx,ebx
ggf_t2_loop:
    cmp rbx,[rsp+80h]
    jae ggf_t2_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+90h]
    call gg_read_u64
    test eax,eax
    jnz ggf_done
    mov rcx,r12
    lea rdx,[rsp+40h]
    mov r8,[rsp+90h]
    call gg_advance
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0A0h]
    call gg_read_u32
    test eax,eax
    jnz ggf_done
    mov eax,dword ptr [rsp+0A0h]
    test eax,eax
    jz ggf_format
    cmp eax,8
    ja ggf_format
    mov ecx,eax
    shl rcx,3
    mov r8,rcx
    mov rcx,r12
    lea rdx,[rsp+40h]
    call gg_advance
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    mov r8d,4
    call gg_advance
    test eax,eax
    jnz ggf_done

    mov rcx,r12
    lea rdx,[rsp+40h]
    lea r8,[rsp+0D0h]
    call gg_read_u64
    test eax,eax
    jnz ggf_done

    mov rax,[rsp+0D0h]
    cmp rax,[rsp+58h]
    jbe ggf_t2_next
    cmp rax,[rsp+68h]
    jae ggf_t2_next
    mov [rsp+68h],rax
ggf_t2_next:
    inc rbx
    jmp ggf_t2_loop

ggf_t2_done:
    mov rax,[rsp+0A8h]
    add rax,[rsp+58h]
    jc ggf_over
    mov [rsp+0C0h],rax               ; absolute offset
    cmp rax,[r12].SSFileCtx.file_bytes
    jae ggf_range

    mov rcx,[rsp+68h]
    cmp rcx,0FFFFFFFFFFFFFFFFh
    je ggf_last_tensor
    sub rcx,[rsp+58h]
    jbe ggf_range
    mov [rsp+0C8h],rcx               ; storage bytes
    jmp ggf_fill

ggf_last_tensor:
    mov rcx,[r12].SSFileCtx.file_bytes
    sub rcx,[rsp+0C0h]
    jbe ggf_range
    mov [rsp+0C8h],rcx

ggf_fill:
    mov qword ptr [r15].SSTensorDesc.found,1
    mov rax,[rsp+50h]
    mov [r15].SSTensorDesc.which_name,rax
    mov rax,[rsp+58h]
    mov [r15].SSTensorDesc.relative_offset,rax
    mov rax,[rsp+0C0h]
    mov [r15].SSTensorDesc.absolute_offset,rax
    mov rax,[rsp+0C8h]
    mov [r15].SSTensorDesc.storage_bytes,rax
    mov rax,[rsp+60h]
    mov [r15].SSTensorDesc.element_count,rax
    mov rax,[rsp+0A8h]
    mov [r15].SSTensorDesc.data_base,rax
    mov rax,[rsp+48h]
    mov [r15].SSTensorDesc.alignment,rax
    mov eax,dword ptr [rsp+70h]
    mov [r15].SSTensorDesc.tensor_type,eax
    mov eax,dword ptr [rsp+74h]
    mov [r15].SSTensorDesc.n_dims,eax
    mov rax,[rsp+0F0h]
    mov [r15].SSTensorDesc.dim0,rax
    mov rax,[rsp+0F8h]
    mov [r15].SSTensorDesc.dim1,rax
    xor eax,eax
    jmp ggf_done

ggf_not_found:
    mov eax,SS_E_NOT_FOUND
    jmp ggf_done
ggf_over:
    mov eax,SS_E_OVERFLOW
    jmp ggf_done
ggf_range:
    mov eax,SS_E_RANGE
    jmp ggf_done
ggf_format:
    mov eax,SS_E_FORMAT
    jmp ggf_done
ggf_bad:
    mov eax,SS_E_INVALID

ggf_done:
    add rsp,100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ss_gguf_find_tensor2 ENDP

END
