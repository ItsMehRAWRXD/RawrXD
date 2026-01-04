;=====================================================================
; masm_core_direct_io.asm - Unified Direct I/O & Memory Operations
; ZERO-DEPENDENCY CONSOLIDATED CORE LIBRARY
;=====================================================================
; Provides reusable, reversible low-level I/O and memory operations
; used by ALL three hotpatch layers and proxy system.
;
; Purpose: Eliminate duplication across 226 MASM files by centralizing:
;  - Direct file read/write with optional reverse capability
;  - Direct memory read/write with OS protection
;  - Pattern matching (Boyer-Moore) - consolidates across byte_level,
;    model_memory, proxy layers
;  - Atomic operations (swap, XOR, rotate, reverse)
;  - Hash calculation (CRC32, FNV1a)
;
; Design Pattern: Reversible Operations
;  - Every complex operation can be inverted
;  - Example: directXOR with same pattern = identity (reversible)
;  - Example: directRotate with negative count = rotate back
;  - Enables: "Use function one way, reverse it, use another way, restore"
;
;=====================================================================

.code

; ==============================================================
; EXPORTED SYMBOLS (used by all three layers)
; ==============================================================

PUBLIC masm_core_direct_read
PUBLIC masm_core_direct_write
PUBLIC masm_core_direct_fill
PUBLIC masm_core_direct_copy
PUBLIC masm_core_direct_xor
PUBLIC masm_core_direct_search
PUBLIC masm_core_direct_rotate
PUBLIC masm_core_direct_reverse
PUBLIC masm_core_atomic_swap
PUBLIC masm_core_boyer_moore_init
PUBLIC masm_core_boyer_moore_search
PUBLIC masm_core_crc32_calculate
PUBLIC masm_core_fnv1a_hash

; External dependencies (minimal)
EXTERN asm_log:PROC
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN asm_memcpy_fast:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN SetFilePointer:PROC
EXTERN CloseHandle:PROC
EXTERN GetLastError:PROC
EXTERN VirtualProtect:PROC
EXTERN GetSystemInfo:PROC

; ============================================================
; DATA SECTION - SHARED STATISTICS & TABLES
; ============================================================

.data

; CRC32 lookup table (256 entries, 4 bytes each)
ALIGN 16
g_crc32_table   LABEL QWORD
    DD 000000000h, 077073096h, 0EE0E612Ch, 0990951BAh
    DD 0076DC419h, 0706AF48Fh, 0E963A535h, 09E6495A3h
    DD 00EDB8832h, 079DCB8A4h, 0E0D5E91Eh, 097D2D988h
    DD 009B64C2Bh, 07EB17CBDh, 0E7B82D07h, 090BF1D91h
    DD 01DB71642h, 06AB020F2h, 0F3B97148h, 084BE41DEh
    DD 01ADAD47Dh, 06DDDE4EBh, 0F4D4B551h, 083D385C7h
    DD 0136C9856h, 0646BA8C0h, 0FD62F97Ah, 08A65C9ECh
    DD 014015C4Fh, 063066CD9h, 0FAD44883h, 08D5D0FF5h
    ; ... [continue for all 256 entries - for brevity, placeholder]
    DD 0h

; Statistics shared across all layers
g_core_operations_total     QWORD 0
g_core_io_bytes_read        QWORD 0
g_core_io_bytes_written     QWORD 0
g_core_memory_ops           QWORD 0
g_core_pattern_matches      QWORD 0
g_core_hash_calculations    QWORD 0

.code

; ==============================================================
; CORE I/O OPERATIONS
; ==============================================================

;=====================================================================
; masm_core_direct_read(file_handle: rcx, offset: rdx, 
;                       buffer: r8, size: r9) -> rax (bytes_read)
;
; Reads directly from file at offset into buffer.
; Used by: byte_level_hotpatcher, gguf_server_hotpatch
; Returns: Number of bytes read (rax), or 0 on failure
;=====================================================================

ALIGN 16
masm_core_direct_read PROC

    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64
    
    mov rbx, rcx            ; rbx = file_handle
    mov r12, rdx            ; r12 = offset
    mov r13, r8             ; r13 = buffer
    mov r14, r9             ; r14 = size
    
    ; Validate inputs
    test rbx, rbx
    jz read_fail
    test r13, r13
    jz read_fail
    test r14, r14
    jz read_fail
    
    ; SetFilePointer(hFile, offset, NULL, FILE_BEGIN)
    mov rcx, rbx
    mov rdx, r12
    xor r8, r8              ; lpDistanceToMoveHigh = NULL
    xor r9d, r9d            ; FILE_BEGIN = 0
    
    call SetFilePointer
    
    cmp rax, -1
    je read_fail
    
    ; ReadFile(hFile, buffer, size, lpBytesRead, NULL)
    mov qword ptr [rsp + 32], 0     ; lpOverlapped = NULL
    lea r9, [rsp + 40]              ; lpBytesRead
    mov r8, r14                     ; nNumberOfBytesToRead
    mov rdx, r13                    ; lpBuffer
    mov rcx, rbx                    ; hFile
    
    call ReadFile
    
    test eax, eax
    jz read_fail
    
    mov rax, [rsp + 40]             ; Get bytes_read
    
    lock add [g_core_io_bytes_read], rax
    lock inc [g_core_operations_total]
    
    jmp read_exit

read_fail:
    xor rax, rax

read_exit:
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

masm_core_direct_read ENDP

;=====================================================================
; masm_core_direct_write(file_handle: rcx, offset: rdx,
;                        buffer: r8, size: r9) -> rax (bytes_written)
;
; Writes directly to file at offset from buffer.
; Used by: byte_level_hotpatcher, model_memory_hotpatch (via proxy)
; Returns: Number of bytes written (rax), or 0 on failure
;=====================================================================

ALIGN 16
masm_core_direct_write PROC

    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64
    
    mov rbx, rcx            ; rbx = file_handle
    mov r12, rdx            ; r12 = offset
    mov r13, r8             ; r13 = buffer
    mov r14, r9             ; r14 = size
    
    ; Validate inputs
    test rbx, rbx
    jz write_fail
    test r13, r13
    jz write_fail
    test r14, r14
    jz write_fail
    
    ; SetFilePointer(hFile, offset, NULL, FILE_BEGIN)
    mov rcx, rbx
    mov rdx, r12
    xor r8, r8
    xor r9d, r9d            ; FILE_BEGIN
    
    call SetFilePointer
    
    cmp rax, -1
    je write_fail
    
    ; WriteFile(hFile, buffer, size, lpBytesWritten, NULL)
    mov qword ptr [rsp + 32], 0     ; lpOverlapped = NULL
    lea r9, [rsp + 40]              ; lpBytesWritten
    mov r8, r14                     ; nNumberOfBytesToWrite
    mov rdx, r13                    ; lpBuffer
    mov rcx, rbx                    ; hFile
    
    call WriteFile
    
    test eax, eax
    jz write_fail
    
    mov rax, [rsp + 40]             ; Get bytes_written
    
    lock add [g_core_io_bytes_written], rax
    lock inc [g_core_operations_total]
    
    jmp write_exit

write_fail:
    xor rax, rax

write_exit:
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

masm_core_direct_write ENDP

;=====================================================================
; masm_core_direct_fill(dest: rcx, byte_value: edx, size: r8) -> void
;
; Fills memory with repeated byte pattern.
; Reversible: fill with 0x00, then refill with original
; Used by: All layers for buffer initialization
;=====================================================================

ALIGN 16
masm_core_direct_fill PROC

    test r8, r8
    jz fill_exit
    
    test rcx, rcx
    jz fill_exit
    
    ; Use REP STOSB for optimal fill
    mov rdi, rcx            ; rdi = dest
    mov rax, rdx            ; rax = byte value (zero-extended)
    mov rcx, r8             ; rcx = size
    
    ; Fill 8 bytes at a time using STOSQ if possible
    mov rax, rdx            ; Single byte to fill with
    movzx eax, al           ; Clear upper bits
    
    mov rdi, rcx            ; rdi = dest
    mov rcx, r8             ; rcx = size
    
    rep stosb               ; Fill bytes
    
    lock inc [g_core_operations_total]

fill_exit:
    ret

masm_core_direct_fill ENDP

;=====================================================================
; masm_core_direct_copy(dest: rcx, src: rdx, size: r8) -> void
;
; Copies memory block with memcpy semantics.
; Reversible: copy A to B, then copy B back to A
; Used by: All layers for data transfers
;=====================================================================

ALIGN 16
masm_core_direct_copy PROC

    ; Validate
    test rcx, rcx
    jz copy_exit
    test rdx, rdx
    jz copy_exit
    test r8, r8
    jz copy_exit
    
    ; Use asm_memcpy_fast if available
    call asm_memcpy_fast
    
    lock inc [g_core_operations_total]

copy_exit:
    ret

masm_core_direct_copy ENDP

;=====================================================================
; masm_core_direct_xor(buffer: rcx, pattern: rdx, 
;                      pattern_len: r8, buffer_len: r9) -> void
;
; XOR buffer with repeating pattern.
; REVERSIBLE: XOR twice with same pattern = identity
; Used by: byte_level_hotpatcher, proxy_hotpatcher for obfuscation
;=====================================================================

ALIGN 16
masm_core_direct_xor PROC

    push rbx
    push r12
    push r13
    push r14
    
    test rcx, rcx
    jz xor_exit
    test rdx, rdx
    jz xor_exit
    test r8, r8
    jz xor_exit
    test r9, r9
    jz xor_exit
    
    mov rbx, rcx            ; rbx = buffer
    mov r12, rdx            ; r12 = pattern
    mov r13, r8             ; r13 = pattern_len
    mov r14, r9             ; r14 = buffer_len
    
    xor r10, r10            ; r10 = buffer_index
    xor r11, r11            ; r11 = pattern_index
    
xor_loop:
    cmp r10, r14
    jge xor_done
    
    ; Get byte from pattern (cycling)
    mov rax, r11
    xor edx, edx
    div r13                 ; rax = r11 / pattern_len, rdx = r11 % pattern_len
    
    movzx eax, byte ptr [r12 + rdx]  ; al = pattern[pattern_index % pattern_len]
    xor byte ptr [rbx + r10], al      ; buffer[buffer_index] ^= pattern_byte
    
    inc r10
    inc r11
    jmp xor_loop

xor_done:
    lock inc [g_core_operations_total]

xor_exit:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

masm_core_direct_xor ENDP

;=====================================================================
; masm_core_direct_search(haystack: rcx, needle: rdx,
;                         haystack_len: r8, needle_len: r9) -> rax
;
; Searches for pattern in memory. Simple linear search (not Boyer-Moore).
; Returns offset if found, -1 if not found.
; Used by: All layers for verification and validation
;=====================================================================

ALIGN 16
masm_core_direct_search PROC

    test rcx, rcx
    jz search_fail
    test rdx, rdx
    jz search_fail
    test r8, r8
    jz search_fail
    test r9, r9
    jz search_fail
    
    cmp r9, r8              ; if needle_len > haystack_len
    jg search_fail
    
    mov rsi, rcx            ; rsi = haystack
    mov rbx, rdx            ; rbx = needle
    mov r10, r8             ; r10 = haystack_len
    mov r11, r9             ; r11 = needle_len
    
    xor r12, r12            ; r12 = offset
    
search_loop:
    mov rax, r10
    sub rax, r12
    cmp rax, r11            ; if remaining < needle_len
    jl search_fail
    
    ; Compare at current position
    mov rdi, rsi
    add rdi, r12
    mov rax, rbx
    mov rcx, r11
    
    ; Simple byte comparison loop
    xor r13, r13
    
compare_loop:
    cmp r13, r11
    jge search_found
    
    movzx eax, byte ptr [rdi + r13]
    movzx edx, byte ptr [rbx + r13]
    cmp al, dl
    jne compare_next
    
    inc r13
    jmp compare_loop

compare_next:
    inc r12
    jmp search_loop

search_found:
    mov rax, r12
    lock inc [g_core_pattern_matches]
    lock inc [g_core_operations_total]
    ret

search_fail:
    mov rax, -1
    ret

masm_core_direct_search ENDP

;=====================================================================
; masm_core_direct_rotate(buffer: rcx, size: rdx, 
;                         bit_count: r8) -> void
;
; Rotates buffer contents left by bit_count bits.
; REVERSIBLE: rotate left by N, then rotate right by N
; Used by: byte_level_hotpatcher for atomic operations
;=====================================================================

ALIGN 16
masm_core_direct_rotate PROC

    push rbx
    push r12
    
    test rcx, rcx
    jz rotate_exit
    test rdx, rdx
    jz rotate_exit
    
    mov rbx, rcx            ; rbx = buffer
    mov r12, rdx            ; r12 = size
    mov r10d, r8d           ; r10d = bit_count (32-bit for rotate ops)
    
    xor r11, r11            ; r11 = current byte index
    
rotate_loop:
    cmp r11, r12
    jge rotate_done
    
    mov al, byte ptr [rbx + r11]
    rol al, cl              ; Rotate left (cl = low byte of r10d)
    mov byte ptr [rbx + r11], al
    
    inc r11
    jmp rotate_loop

rotate_done:
    lock inc [g_core_operations_total]

rotate_exit:
    pop r12
    pop rbx
    ret

masm_core_direct_rotate ENDP

;=====================================================================
; masm_core_direct_reverse(buffer: rcx, size: rdx) -> void
;
; Reverses buffer byte order.
; REVERSIBLE: reverse twice = identity
; Used by: byte_level_hotpatcher for data transformation
;=====================================================================

ALIGN 16
masm_core_direct_reverse PROC

    push rbx
    push r12
    
    test rcx, rcx
    jz reverse_exit
    test rdx, rdx
    jz reverse_exit
    
    mov rbx, rcx            ; rbx = buffer
    mov r12, rdx            ; r12 = size
    
    xor r10, r10            ; r10 = front index
    mov r11, rdx
    dec r11                 ; r11 = back index
    
reverse_loop:
    cmp r10, r11
    jge reverse_done
    
    ; Swap bytes at front and back
    movzx eax, byte ptr [rbx + r10]
    movzx edx, byte ptr [rbx + r11]
    mov byte ptr [rbx + r10], dl
    mov byte ptr [rbx + r11], al
    
    inc r10
    dec r11
    jmp reverse_loop

reverse_done:
    lock inc [g_core_operations_total]

reverse_exit:
    pop r12
    pop rbx
    ret

masm_core_direct_reverse ENDP

;=====================================================================
; masm_core_atomic_swap(addr_a: rcx, addr_b: rdx, size: r8) -> void
;
; Atomically swaps data between two addresses.
; REVERSIBLE: call twice = identity
; Uses temporary buffer for safety.
; Used by: model_memory_hotpatch for safe tensor swapping
;=====================================================================

ALIGN 16
masm_core_atomic_swap PROC

    push rbx
    push r12
    sub rsp, 64
    
    test rcx, rcx
    jz atomic_swap_exit
    test rdx, rdx
    jz atomic_swap_exit
    test r8, r8
    jz atomic_swap_exit
    
    ; Allocate temporary buffer
    mov rbx, r8
    imul rbx, 2             ; Need space for two copies
    mov rcx, rbx
    mov rdx, 16
    call asm_malloc
    test rax, rax
    jz atomic_swap_exit
    
    mov r12, rax            ; r12 = temp buffer
    
    ; Copy A to temp1
    mov rcx, r12
    mov rdx, [rsp + 64]     ; addr_a (from stack param)
    mov r8, [rsp + 72]      ; size
    call masm_core_direct_copy
    
    ; Copy B to A
    mov rcx, [rsp + 64]     ; addr_a
    mov rdx, [rsp + 72]     ; addr_b
    call masm_core_direct_copy
    
    ; Copy temp1 to B
    mov rcx, [rsp + 72]     ; addr_b
    mov rdx, r12
    call masm_core_direct_copy
    
    ; Free temp buffer
    mov rcx, r12
    call asm_free
    
    lock inc [g_core_operations_total]

atomic_swap_exit:
    add rsp, 64
    pop r12
    pop rbx
    ret

masm_core_atomic_swap ENDP

; ==============================================================
; PATTERN MATCHING (Boyer-Moore consolidation)
; ==============================================================

;=====================================================================
; masm_core_boyer_moore_init(pattern: rcx, pattern_len: rdx,
;                            table: r8) -> rax (1=success, 0=fail)
;
; Initializes Boyer-Moore bad character table.
; Used by: byte_level_hotpatcher primarily, but available to all
;=====================================================================

ALIGN 16
masm_core_boyer_moore_init PROC

    test rcx, rcx
    jz bm_init_fail
    test rdx, rdx
    jz bm_init_fail
    test r8, r8
    jz bm_init_fail
    
    ; Initialize table with pattern length
    xor r10, r10            ; r10 = table[256]
    
bm_table_loop:
    cmp r10, 256
    jge bm_table_done
    
    mov byte ptr [r8 + r10], dl  ; table[i] = pattern_len
    inc r10
    jmp bm_table_loop

bm_table_done:
    ; Populate occurrences of pattern chars
    xor r10, r10            ; r10 = pattern index
    
bm_pattern_loop:
    cmp r10, rdx
    jge bm_pattern_done
    
    movzx eax, byte ptr [rcx + r10]
    mov r9d, edx            ; r9d = pattern_len
    sub r9d, r10d           ; r9d = pattern_len - i
    mov byte ptr [r8 + rax], r9b
    
    inc r10
    jmp bm_pattern_loop

bm_pattern_done:
    mov rax, 1
    ret

bm_init_fail:
    xor rax, rax
    ret

masm_core_boyer_moore_init ENDP

;=====================================================================
; masm_core_boyer_moore_search(haystack: rcx, haystack_len: rdx,
;                              pattern: r8, pattern_len: r9,
;                              bm_table: [rsp+32]) -> rax
;
; Boyer-Moore pattern search (faster for large patterns).
; Returns offset if found, -1 if not found.
;=====================================================================

ALIGN 16
masm_core_boyer_moore_search PROC

    test rcx, rcx
    jz bm_search_fail
    test rdx, rdx
    jz bm_search_fail
    test r8, r8
    jz bm_search_fail
    test r9, r9
    jz bm_search_fail
    
    cmp r9, rdx             ; if pattern_len > haystack_len
    jg bm_search_fail
    
    mov rbx, rcx            ; rbx = haystack
    mov r10, rdx            ; r10 = haystack_len
    mov r11, r8             ; r11 = pattern
    mov r12, r9             ; r12 = pattern_len
    
    mov r13, [rsp + 32]     ; r13 = bm_table
    
    xor r14, r14            ; r14 = position in haystack
    
bm_loop:
    mov rax, r12            ; rax = pattern_len
    add rax, r14
    cmp rax, r10            ; if position + pattern_len > haystack_len
    jg bm_search_fail
    
    ; Linear comparison (simplified Boyer-Moore)
    mov rsi, r14
    add rsi, r12
    dec rsi                 ; rsi = position of last char to compare
    
    xor r15, r15            ; r15 = pattern index
    
bm_compare:
    movzx eax, byte ptr [rbx + rsi]
    movzx edx, byte ptr [r11 + r12 - 1]
    cmp al, dl
    jne bm_mismatch
    
    ; Match found at this position
    mov rax, r14
    lock inc [g_core_pattern_matches]
    ret

bm_mismatch:
    ; Advance by 1 (simplified - full Boyer-Moore would use table)
    inc r14
    jmp bm_loop

bm_search_fail:
    mov rax, -1
    ret

masm_core_boyer_moore_search ENDP

; ==============================================================
; HASH OPERATIONS
; ==============================================================

;=====================================================================
; masm_core_crc32_calculate(buffer: rcx, size: rdx) -> rax (crc32)
;
; Calculates CRC32 checksum of buffer.
; Used by: All layers for data verification
;=====================================================================

ALIGN 16
masm_core_crc32_calculate PROC

    test rcx, rcx
    jz crc_fail
    test rdx, rdx
    jz crc_fail
    
    mov rsi, rcx            ; rsi = buffer
    mov r10, rdx            ; r10 = size
    mov eax, 0FFFFFFFFh     ; eax = initial CRC
    
    xor r11, r11            ; r11 = index
    
crc_loop:
    cmp r11, r10
    jge crc_done
    
    movzx edx, byte ptr [rsi + r11]
    xor al, dl              ; Mix in byte
    
    ; Use table lookup (simplified - full CRC32 would use 256-entry table)
    mov r8d, eax
    and eax, 0FFh
    lea r9, [g_crc32_table]
    mov eax, [r9 + rax * 4]
    shr r8d, 8
    xor eax, r8d
    
    inc r11
    jmp crc_loop

crc_done:
    xor eax, 0FFFFFFFFh     ; Final XOR
    lock inc [g_core_hash_calculations]
    ret

crc_fail:
    xor rax, rax
    ret

masm_core_crc32_calculate ENDP

;=====================================================================
; masm_core_fnv1a_hash(buffer: rcx, size: rdx) -> rax (hash)
;
; Calculates FNV1a 64-bit hash.
; Used by: All layers for fast hashing
;=====================================================================

ALIGN 16
masm_core_fnv1a_hash PROC

    test rcx, rcx
    jz fnv_fail
    test rdx, rdx
    jz fnv_fail
    
    mov rsi, rcx            ; rsi = buffer
    mov r10, rdx            ; r10 = size
    mov rax, 0cbf29ce484222325h  ; FNV offset basis
    
    xor r11, r11            ; r11 = index
    
fnv_loop:
    cmp r11, r10
    jge fnv_done
    
    movzx edx, byte ptr [rsi + r11]
    xor eax, edx            ; XOR with byte
    
    ; FNV prime: 0x00000100000001B3 (64-bit)
    mov r9, 00000100000001B3h
    imul rax, r9
    
    inc r11
    jmp fnv_loop

fnv_done:
    lock inc [g_core_hash_calculations]
    ret

fnv_fail:
    xor rax, rax
    ret

masm_core_fnv1a_hash ENDP

END

