; MASM Hello World TPS Benchmark
; Measures raw token processing throughput in x64 assembly
; Target: Maximum TPS for simple operations

include rawr_imports.inc

.data
    ; Benchmark configuration
    ITERATIONS equ 1000000      ; 1M iterations for stable measurement
    WARMUP_ITER equ 100000      ; Warmup iterations
    
    ; Message strings
    msg_start db "=== MASM Hello World TPS Benchmark ===", 13, 10, 0
    msg_warmup db "[1/3] Warmup...", 13, 10, 0
    msg_benchmark db "[2/3] Benchmarking...", 13, 10, 0
    msg_results db "[3/3] Results:", 13, 10, 0
    msg_tps db "TPS: ", 0
    msg_ns_per_op db "ns/op: ", 0
    msg_total_ops db "Total operations: ", 0
    msg_time db "Total time (ms): ", 0
    msg_newline db 13, 10, 0
    msg_done db "Benchmark complete.", 13, 10, 0
    
    ; Output buffer for number formatting
    num_buffer db 32 dup(0)
    
    ; Timing variables
    start_time dq 0
    end_time dq 0
    freq dq 0
    
    ; Results
    total_ops dq ITERATIONS
    elapsed_ns dq 0
    tps_scaled dq 0  ; TPS * 1000 for fixed-point

.code

; ============================================================================
; Entry point
; ============================================================================
mainCRTStartup PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Print header
    lea rcx, msg_start
    call rawr_print_string
    
    ; Get frequency for timing
    lea rcx, freq
    call QueryPerformanceFrequency
    
    ; Warmup phase
    lea rcx, msg_warmup
    call rawr_print_string
    
    mov rcx, WARMUP_ITER
    call run_benchmark_loop
    
    lea rcx, msg_newline
    call rawr_print_string
    
    ; Benchmark phase
    lea rcx, msg_benchmark
    call rawr_print_string
    
    ; Get start time
    lea rcx, start_time
    call QueryPerformanceCounter
    
    ; Run benchmark
    mov rcx, ITERATIONS
    call run_benchmark_loop
    
    ; Get end time
    lea rcx, end_time
    call QueryPerformanceCounter
    
    lea rcx, msg_newline
    call rawr_print_string
    
    ; Calculate results
    call calculate_results
    
    ; Print results
    call print_results
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 40
    ret
mainCRTStartup ENDP

; ============================================================================
; Benchmark loop - core operation to measure
; ============================================================================
run_benchmark_loop PROC FRAME
    ; rcx = iteration count
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rbx, rcx          ; rbx = remaining iterations
    
benchmark_loop:
    test rbx, rbx
    jz benchmark_done
    dec rbx
    
    ; === CORE OPERATION: Simple token-like processing ===
    ; Simulate minimal token processing workload
    
    ; Load a "token" (simulated)
    mov rax, rbx
    and rax, 0FFh        ; Token ID (0-255)
    
    ; Simple hash/computation (simulates token lookup)
    imul rax, rax, 31    ; hash = token * 31
    xor rax, rbx         ; hash ^= iteration
    
    ; Simulate token emission (store result)
    mov rdi, rax
    
    ; More operations to simulate realistic workload
    shl rax, 3           ; Multiply by 8 (table offset)
    add rax, rdi         ; Add hash
    and rax, 0FFFh       ; Mask to 4KB table
    
    jmp benchmark_loop
    
benchmark_done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
run_benchmark_loop ENDP

; ============================================================================
; Calculate benchmark results
; ============================================================================
calculate_results PROC FRAME
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    ; elapsed = end_time - start_time
    mov rax, end_time
    mov rbx, start_time
    sub rax, rbx
    
    ; Convert to nanoseconds: elapsed * 1000000000 / freq
    ; Using 128-bit intermediate for precision
    xor rdx, rdx
    mov rbx, 1000000000  ; 1 billion ns per second
    mul rbx              ; rax:rdx = elapsed * 1e9
    
    ; Divide by frequency
    mov rbx, freq
    div rbx              ; rax = elapsed_ns
    
    mov elapsed_ns, rax
    
    ; Calculate TPS (tokens per second) scaled by 1000
    ; TPS = (ITERATIONS * 1e9) / elapsed_ns
    ; But we want TPS * 1000, so: (ITERATIONS * 1e12) / elapsed_ns
    
    mov rax, ITERATIONS
    mov rbx, 1000000000000  ; 1e12
    xor rdx, rdx
    mul rbx
    
    mov rbx, elapsed_ns
    test rbx, rbx
    jnz do_divide
    mov rbx, 1           ; Prevent division by zero
    
do_divide:
    div rbx
    mov tps_scaled, rax  ; TPS * 1000
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
calculate_results ENDP

; ============================================================================
; Print benchmark results
; ============================================================================
print_results PROC FRAME
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    lea rcx, msg_results
    call rawr_print_string
    
    ; Print total operations
    lea rcx, msg_total_ops
    call rawr_print_string
    mov rax, total_ops
    call print_uint64
    lea rcx, msg_newline
    call rawr_print_string
    
    ; Print elapsed time in ms
    lea rcx, msg_time
    call rawr_print_string
    mov rax, elapsed_ns
    mov rbx, 1000000     ; Convert ns to ms
    xor rdx, rdx
    div rbx
    call print_uint64
    lea rcx, msg_newline
    call rawr_print_string
    
    ; Print TPS
    lea rcx, msg_tps
    call rawr_print_string
    mov rax, tps_scaled
    mov rbx, 1000
    xor rdx, rdx
    div rbx              ; rax = TPS, rdx = remainder
    call print_uint64_decimal
    lea rcx, msg_newline
    call rawr_print_string
    
    ; Print ns/op
    lea rcx, msg_ns_per_op
    call rawr_print_string
    mov rax, elapsed_ns
    mov rbx, ITERATIONS
    xor rdx, rdx
    div rbx
    call print_uint64
    lea rcx, msg_newline
    call rawr_print_string
    
    lea rcx, msg_newline
    call rawr_print_string
    lea rcx, msg_done
    call rawr_print_string
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
print_results ENDP

; ============================================================================
; Print unsigned 64-bit integer
; ============================================================================
print_uint64 PROC FRAME
    ; rax = number to print
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rbx, rax
    lea rdi, num_buffer + 31  ; Start from end
    mov byte ptr [rdi], 0     ; Null terminate
    
    mov rcx, 10               ; Divisor
    
convert_loop:
    xor rdx, rdx
    mov rax, rbx
    div rcx
    
    add dl, '0'               ; Convert to ASCII
    dec rdi
    mov [rdi], dl
    
    mov rbx, rax
    test rbx, rbx
    jnz convert_loop
    
    ; Print the number
    mov rcx, rdi
    call rawr_print_string
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
print_uint64 ENDP

; ============================================================================
; Print unsigned 64-bit integer with decimal (fixed-point)
; rax = integer part, rdx = remainder (0-999)
; ============================================================================
print_uint64_decimal PROC FRAME
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 40
    
    mov r12, rdx            ; Save remainder
    
    ; Print integer part
    call print_uint64
    
    ; Print decimal point
    mov rcx, '.'
    call putchar
    
    ; Print fractional part (3 digits)
    mov rax, r12
    mov rbx, 100
    xor rdx, rdx
    div rbx                 ; rax = first digit
    
    add al, '0'
    movzx rcx, al
    call putchar
    
    mov rax, rdx
    xor rdx, rdx
    mov rbx, 10
    div rbx                 ; rax = second digit, rdx = third
    
    add al, '0'
    movzx rcx, al
    call putchar
    
    add dl, '0'
    movzx rcx, dl
    call putchar
    
    add rsp, 40
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
print_uint64_decimal ENDP

; ============================================================================
; Print single character
; ============================================================================
putchar PROC FRAME
    ; cl = character
    .allocstack 40
    .endprolog
    
    sub rsp, 40
    
    mov [rsp+48], cl       ; Store character on stack
    
    ; WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), &char, 1, &written, NULL)
    mov ecx, -11           ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax           ; hConsoleOutput
    lea rdx, [rsp+48]      ; lpBuffer
    mov r8, 1              ; nNumberOfCharsToWrite
    lea r9, [rsp+56]      ; lpNumberOfCharsWritten
    mov qword ptr [rsp+32], 0  ; lpReserved
    call WriteConsoleA
    
    add rsp, 40
    ret
putchar ENDP

; ============================================================================
; Print null-terminated string
; ============================================================================
rawr_print_string PROC FRAME
    ; rcx = string pointer
    .allocstack 40
    .endprolog
    
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx           ; rdi = string pointer
    
    ; Calculate length
    xor rcx, rcx
    mov rbx, rdi
strlen_loop:
    cmp byte ptr [rbx], 0
    je strlen_done
    inc rbx
    inc rcx
    jmp strlen_loop
strlen_done:
    
    test rcx, rcx
    jz print_done          ; Empty string
    
    ; WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), str, len, &written, NULL)
    mov r8, rcx            ; nNumberOfCharsToWrite = length
    
    mov ecx, -11           ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax           ; hConsoleOutput
    mov rdx, rdi           ; lpBuffer
    lea r9, [rsp+48]       ; lpNumberOfCharsWritten
    mov qword ptr [rsp+32], 0  ; lpReserved
    call WriteConsoleA
    
print_done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
rawr_print_string ENDP

END
