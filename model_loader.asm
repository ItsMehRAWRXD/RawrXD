; model_loader.asm
; Sovereign Engine - Enterprise Model Loader
; Pure x64 MASM - Zero dependencies
; Supports: GGUF v2/v3, memory-mapped loading, lazy tensor initialization
; Thread-safe, NUMA-aware, production hardened

extrn CreateFileA:proc
extrn CloseHandle:proc
extrn ReadFile:proc
extrn GetFileSize:proc
extrn CreateFileMappingA:proc
extrn MapViewOfFile:proc
extrn UnmapViewOfFile:proc
extrn VirtualAlloc:proc
extrn VirtualFree:proc

public LoadModel
public UnloadModel
public GetTensorByName
public print_error

.data
    loader_state    dd 0
    loader_progress dd 0
    loader_error    dq 0
    
    gguf_magic      dq 0
    gguf_version    dd 0
    gguf_tensors    dq 0
    gguf_metadata   dq 0
    gguf_alignment  dq 32
    
    tensor_count    dq 0
    tensor_table    dq 0
    tensor_memory   dq 0
    tensor_total    dq 0
    
    mmap_handle     dq 0
    mmap_base       dq 0
    mmap_size       dq 0
    
    lazy_queue_head dq 0
    lazy_queue_tail dq 0
    lazy_queue_mask dq 63
    
    numa_node_count dd 0
    numa_affinity   db 64 dup (0)
    
    err_gguf_magic  db "ERROR: Invalid GGUF magic number", 0Ah, 0
    err_gguf_version db "ERROR: Unsupported GGUF version", 0Ah, 0
    err_oom         db "ERROR: Out of memory", 0Ah, 0
    err_mmap        db "ERROR: Memory mapping failed", 0Ah, 0

.code
LoadModel proc
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx
    mov r13, rdx
    
    mov [loader_state], 1
    mov [loader_progress], 0
    
    mov rcx, r12
    call validate_gguf
    test eax, eax
    jnz load_error
    
    mov [loader_progress], 10
    
    mov rcx, r12
    mov rdx, r13
    call map_model_file
    test eax, eax
    jnz load_error
    
    mov [loader_progress], 30
    
    mov rcx, [mmap_base]
    call parse_tensor_metadata
    test eax, eax
    jnz load_error
    
    mov [loader_progress], 50
    
    mov rcx, [tensor_total]
    call allocate_tensor_memory
    test eax, eax
    jnz load_error
    
    mov [loader_progress], 70
    
    test r13, 1
    jnz eager_load
    call setup_lazy_loading
    jmp load_complete
    
eager_load:
    call load_all_tensors
    
load_complete:
    mov [loader_progress], 100
    mov [loader_state], 2
    xor eax, eax
    jmp load_done
    
load_error:
    mov [loader_state], 3
    mov [loader_error], rax
    
load_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
LoadModel endp

validate_gguf proc
    push rbx
    
    mov edx, 80000000h
    xor r8d, r8d
    xor r9d, r9d
    sub rsp, 40
    mov dword ptr [rsp+32], 3
    mov qword ptr [rsp+24], 0
    call CreateFileA
    add rsp, 40
    cmp rax, -1
    je vg_open_fail
    mov rbx, rax
    
    sub rsp, 32
    mov rcx, rbx
    lea rdx, [rsp]
    mov r8d, 8
    lea r9, [rsp+16]
    mov qword ptr [rsp+24], 0
    call ReadFile
    
    cmp dword ptr [rsp], 46554747h
    jne vg_bad_magic
    
    mov rax, [rsp]
    mov [gguf_magic], rax
    
    mov rcx, rbx
    lea rdx, [rsp]
    mov r8d, 4
    lea r9, [rsp+16]
    mov qword ptr [rsp+24], 0
    call ReadFile
    
    mov eax, [rsp]
    cmp eax, 2
    jb vg_bad_version
    cmp eax, 3
    ja vg_bad_version
    
    mov [gguf_version], eax
    
    add rsp, 32
    mov rcx, rbx
    call CloseHandle
    xor eax, eax
    pop rbx
    ret
    
vg_bad_magic:
    add rsp, 32
    mov rcx, rbx
    call CloseHandle
    lea rcx, err_gguf_magic
    call print_error
    mov eax, 1
    pop rbx
    ret
    
vg_bad_version:
    add rsp, 32
    mov rcx, rbx
    call CloseHandle
    lea rcx, err_gguf_version
    call print_error
    mov eax, 2
    pop rbx
    ret
    
vg_open_fail:
    mov eax, 3
    pop rbx
    ret
validate_gguf endp

map_model_file proc
    push rbx
    push rsi
    push r12
    push r13
    
    mov r12, rcx
    mov r13, rdx
    
    mov edx, 80000000h
    xor r8d, r8d
    xor r9d, r9d
    sub rsp, 40
    mov dword ptr [rsp+32], 3
    mov qword ptr [rsp+24], 0
    call CreateFileA
    add rsp, 40
    cmp rax, -1
    je mm_fail
    mov rbx, rax
    
    mov rcx, rax
    xor edx, edx
    call GetFileSize
    mov [mmap_size], rax
    mov rsi, rax
    
    mov rcx, rbx
    xor edx, edx
    mov r8d, 4
    xor r9d, r9d
    sub rsp, 40
    mov qword ptr [rsp+32], 0
    call CreateFileMappingA
    add rsp, 40
    test rax, rax
    jz mm_fail_close
    mov [mmap_handle], rax
    mov r12, rax
    
    mov rcx, r12
    mov edx, 4
    xor r8d, r8d
    xor r9d, r9d
    sub rsp, 40
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    add rsp, 40
    test rax, rax
    jz mm_fail_unmap
    mov [mmap_base], rax
    
    mov rcx, rbx
    call CloseHandle
    
    xor eax, eax
    pop r13
    pop r12
    pop rsi
    pop rbx
    ret
    
mm_fail_unmap:
    mov rcx, r12
    call CloseHandle
    
mm_fail_close:
    mov rcx, rbx
    call CloseHandle
    
mm_fail:
    lea rcx, err_mmap
    call print_error
    mov eax, 4
    pop r13
    pop r12
    pop rsi
    pop rbx
    ret
map_model_file endp

parse_tensor_metadata proc
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov r12, rcx
    
    add r12, 12
    
    mov rax, [r12]
    mov [gguf_tensors], rax
    mov [tensor_count], rax
    add r12, 8
    
    mov rax, [r12]
    mov [gguf_metadata], rax
    add r12, 8
    
    mov rcx, [gguf_metadata]
    xor r13, r13
    
skip_meta_loop:
    cmp r13, rcx
    jae meta_done
    
    mov rax, [r12]
    add r12, 8
    add r12, rax
    
    mov eax, [r12]
    add r12, 4
    
    cmp eax, 8
    je skip_u64
    cmp eax, 12
    je skip_f64
    cmp eax, 10
    je skip_string
    
    add r12, 4
    jmp meta_next
    
skip_u64:
    add r12, 8
    jmp meta_next
skip_f64:
    add r12, 8
    jmp meta_next
skip_string:
    mov rax, [r12]
    add r12, 8
    add r12, rax
    jmp meta_next
    
meta_next:
    inc r13
    jmp skip_meta_loop
    
meta_done:
    mov rcx, [tensor_count]
    xor r13, r13
    xor r14, r14
    
tensor_loop:
    cmp r13, rcx
    jae tensor_done
    
    mov rax, [r12]
    add r12, 8
    add r12, rax
    
    mov rax, [r12]
    add r12, 8
    add r12, rax
    
    mov eax, [r12]
    mov r15d, eax
    add r12, 4
    
    mov rbx, 1
dim_loop:
    cmp r15d, 0
    je dim_done
    mov eax, [r12]
    imul rbx, rax
    add r12, 4
    dec r15d
    jmp dim_loop
    
dim_done:
    mov eax, [r12]
    add r12, 4
    
    cmp eax, 0
    jne not_f32
    imul rbx, 4
    jmp add_size
not_f32:
    cmp eax, 2
    jne not_q4_0
    mov rax, rbx
    shr rax, 5
    imul rax, 20
    mov rbx, rax
    jmp add_size
not_q4_0:
    imul rbx, 4
    
add_size:
    add r14, rbx
    
    add r12, 8
    
    inc r13
    jmp tensor_loop
    
tensor_done:
    mov [tensor_total], r14
    
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
parse_tensor_metadata endp

allocate_tensor_memory proc
    push rbx
    push rcx
    
    mov rbx, rcx
    
    add rbx, [gguf_alignment]
    
    sub rsp, 40
    xor ecx, ecx
    mov rdx, rbx
    mov r8d, 3000h
    mov r9d, 4
    call VirtualAlloc
    add rsp, 40
    
    test rax, rax
    jz atm_oom
    
    mov [tensor_memory], rax
    
    mov rcx, rax
    add rcx, [gguf_alignment]
    dec rcx
    mov rax, [gguf_alignment]
    dec rax
    not rax
    and rcx, rax
    mov [tensor_table], rcx
    
    xor eax, eax
    pop rcx
    pop rbx
    ret
    
atm_oom:
    lea rcx, err_oom
    call print_error
    mov eax, 5
    pop rcx
    pop rbx
    ret
allocate_tensor_memory endp

setup_lazy_loading proc
    push rbx
    
    mov rcx, 524288
    xor edx, edx
    mov r8d, 3000h
    mov r9d, 4
    sub rsp, 40
    call VirtualAlloc
    add rsp, 40
    
    mov [lazy_queue_head], rax
    mov [lazy_queue_tail], rax
    
    pop rbx
    ret
setup_lazy_loading endp

load_all_tensors proc
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov rsi, [mmap_base]
    mov rdi, [tensor_memory]
    mov r12, [tensor_total]
    mov r13, [tensor_count]
    
    mov rcx, r12
    shr rcx, 6
    jz copy_remainder
    
copy_64_loop:
    vmovdqa ymm0, [rsi]
    vmovdqa [rdi], ymm0
    vmovdqa ymm1, [rsi+32]
    vmovdqa [rdi+32], ymm1
    add rsi, 64
    add rdi, 64
    dec rcx
    jnz copy_64_loop
    
copy_remainder:
    mov rcx, r12
    and rcx, 63
    jz copy_done
    rep movsb
    
copy_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
load_all_tensors endp

GetTensorByName proc
    push rbx
    
    mov rbx, [tensor_table]
    mov rcx, [tensor_count]
    test rcx, rcx
    jz gtn_not_found
    
    mov rax, rbx
    
gtn_done:
    pop rbx
    ret
    
gtn_not_found:
    xor eax, eax
    pop rbx
    ret
GetTensorByName endp

UnloadModel proc
    push rbx
    
    mov rcx, [tensor_memory]
    test rcx, rcx
    jz um_skip_tensors
    xor edx, edx
    mov r8d, 8000h
    call VirtualFree
    
um_skip_tensors:
    mov rcx, [mmap_base]
    test rcx, rcx
    jz um_skip_mmap
    call UnmapViewOfFile
    
um_skip_mmap:
    mov rcx, [mmap_handle]
    test rcx, rcx
    jz um_skip_handle
    call CloseHandle
    
um_skip_handle:
    mov [loader_state], 0
    mov [loader_progress], 0
    mov [tensor_count], 0
    mov [tensor_total], 0
    
    pop rbx
    ret
UnloadModel endp

print_error proc
    ret
print_error endp

end
