; ==============================================================================
; bench_deep2.asm - Deep2 Bare-Metal Benchmark Harness
; No CRT, pure x64 Win32 API. Measures Deep2 kernel throughput.
; ==============================================================================

extrn GetStdHandle : proc
extrn WriteFile : proc
extrn VirtualAlloc : proc
extrn VirtualFree : proc
extrn QueryPerformanceFrequency : proc
extrn QueryPerformanceCounter : proc
extrn ExitProcess : proc
extrn Deep2_VecDotProduct : proc
extrn Deep2_SwiGLU : proc
extrn Deep2_RMSNorm : proc

; Win32 Constants
STD_OUTPUT_HANDLE equ -11
MEM_COMMIT        equ 1000h
MEM_RESERVE       equ 2000h
PAGE_READWRITE    equ 04h
MEM_RELEASE       equ 8000h

.data
    align 8
    qpf           dq 0
    qpcStart      dq 0
    qpcEnd        dq 0
    
    hConsole      dq 0
    bytesWritten  dq 0

    ; Output strings
    msgStart      db "Starting Deep2 Kernel Benchmark...", 10, 13
    msgStartLen   equ $ - msgStart
    
    msgVecDot     db "Testing VecDotProduct...", 10, 13
    msgVecDotLen  equ $ - msgVecDot
    
    msgSwiGLU     db "Testing SwiGLU...", 10, 13
    msgSwiGLULen  equ $ - msgSwiGLU
    
    msgRMSNorm    db "Testing RMSNorm...", 10, 13
    msgRMSNormLen equ $ - msgRMSNorm
    
    msgTicks      db "Elapsed Ticks: "
    msgTicksLen   equ $ - msgTicks
    
    msgGBps       db "Throughput: "
    msgGBpsLen    equ $ - msgGBps
    
    msgTPS        db "Projected 40GB TPS: "
    msgTPSLen     equ $ - msgTPS
    
    msgDone       db "Benchmark Complete.", 10, 13
    msgDoneLen    equ $ - msgDone
    
    newline       db 10, 13
    space         db " "
    gbSuffix      db " GB/s", 10, 13
    tpsSuffix     db " tokens/sec", 10, 13

    ; Allocation sizes (256MB per tensor)
    tensorSize    equ 1024 * 1024 * 256
    vecElements   equ 1024 * 1024 * 64    ; 64M elements for vector ops
    iters         equ 1000

    ; Buffer for number formatting
    numBuffer     db 32 dup(0)
    
    ; Results
    resultBuffer  dd 0

.code
main proc
    ; Standard x64 shadow space + alignment
    sub rsp, 40h

    ; 1. Get STDOUT handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hConsole, rax

    ; Print startup message
    mov rcx, hConsole
    lea rdx, msgStart
    mov r8, msgStartLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; 2. Cache Performance Frequency
    lea rcx, qpf
    call QueryPerformanceFrequency

    ; 3. Allocate Dummy Tensors (256MB each, aligned)
    xor rcx, rcx                ; lpAddress = NULL
    mov rdx, tensorSize         ; dwSize
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    mov r12, rax                ; r12 = Tensor A ptr

    xor rcx, rcx
    mov rdx, tensorSize
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    mov r13, rax                ; r13 = Tensor B ptr

    xor rcx, rcx
    mov rdx, tensorSize
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    mov r14, rax                ; r14 = Output ptr

    ; Initialize tensors with dummy data (1.0f)
    mov rdi, r12
    mov rcx, vecElements
    mov eax, 03f800000h         ; 1.0f in IEEE 754
@@init_a:
    mov dword ptr [rdi], eax
    add rdi, 4
    dec rcx
    jnz @@init_a

    mov rdi, r13
    mov rcx, vecElements
@@init_b:
    mov dword ptr [rdi], eax
    add rdi, 4
    dec rcx
    jnz @@init_b

    ; ========================================================================
    ; BENCHMARK 1: VecDotProduct
    ; ========================================================================
    mov rcx, hConsole
    lea rdx, msgVecDot
    mov r8, msgVecDotLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Start QPC
    lea rcx, qpcStart
    call QueryPerformanceCounter

    ; Hot loop: VecDotProduct
    mov r15, iters
@@vecdot_loop:
    mov rcx, r12              ; a
    mov rdx, r13              ; b
    lea r8, resultBuffer      ; out
    mov r9, vecElements       ; n
    call Deep2_VecDotProduct
    dec r15
    jnz @@vecdot_loop

    ; End QPC
    lea rcx, qpcEnd
    call QueryPerformanceCounter

    ; Calculate and display results
    call CalculateAndDisplay

    ; ========================================================================
    ; BENCHMARK 2: SwiGLU
    ; ========================================================================
    mov rcx, hConsole
    lea rdx, msgSwiGLU
    mov r8, msgSwiGLULen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Start QPC
    lea rcx, qpcStart
    call QueryPerformanceCounter

    ; Hot loop: SwiGLU
    mov r15, iters
@@swiglu_loop:
    mov rcx, r12              ; x
    mov rdx, r13              ; y
    mov r8, r14               ; out
    mov r9, vecElements       ; n
    call Deep2_SwiGLU
    dec r15
    jnz @@swiglu_loop

    ; End QPC
    lea rcx, qpcEnd
    call QueryPerformanceCounter

    call CalculateAndDisplay

    ; ========================================================================
    ; BENCHMARK 3: RMSNorm
    ; ========================================================================
    mov rcx, hConsole
    lea rdx, msgRMSNorm
    mov r8, msgRMSNormLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Start QPC
    lea rcx, qpcStart
    call QueryPerformanceCounter

    ; Hot loop: RMSNorm
    mov r15, iters
@@rmsnorm_loop:
    mov rcx, r12              ; x
    mov rdx, r14              ; out
    mov r8, vecElements       ; n
    movss xmm3, dword ptr [epsilon]
    call Deep2_RMSNorm
    dec r15
    jnz @@rmsnorm_loop

    ; End QPC
    lea rcx, qpcEnd
    call QueryPerformanceCounter

    call CalculateAndDisplay

    ; ========================================================================
    ; Cleanup and Exit
    ; ========================================================================
    mov rcx, hConsole
    lea rdx, msgDone
    mov r8, msgDoneLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Free memory
    mov rcx, r12
    xor rdx, rdx
    mov r8, MEM_RELEASE
    call VirtualFree

    mov rcx, r13
    xor rdx, rdx
    mov r8, MEM_RELEASE
    call VirtualFree

    mov rcx, r14
    xor rdx, rdx
    mov r8, MEM_RELEASE
    call VirtualFree

    ; ExitProcess(0)
    xor rcx, rcx
    call ExitProcess

main endp

; ==============================================================================
; CalculateAndDisplay - Compute and print benchmark results
; ==============================================================================
CalculateAndDisplay proc
    sub rsp, 40h

    ; Calculate Ticks: qpcEnd - qpcStart
    mov rax, qpcEnd
    sub rax, qpcStart
    mov r15, rax                ; r15 = elapsed ticks

    ; Print "Elapsed Ticks: "
    mov rcx, hConsole
    lea rdx, msgTicks
    mov r8, msgTicksLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Print ticks value
    mov rax, r15
    call PrintUint64

    ; Print newline
    mov rcx, hConsole
    lea rdx, newline
    mov r8, 2
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    add rsp, 40h
    ret
CalculateAndDisplay endp

; ==============================================================================
; PrintUint64 - Convert and print unsigned 64-bit integer
; ==============================================================================
PrintUint64 proc
    sub rsp, 40h
    
    lea rdi, numBuffer
    add rdi, 31
    mov byte ptr [rdi], 0
    mov rbx, 10
@@itoa_loop:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz @@itoa_loop

    ; Calculate length
    lea rax, numBuffer
    add rax, 31
    sub rax, rdi
    mov r8, rax

    ; Write to console
    mov rcx, hConsole
    mov rdx, rdi
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    add rsp, 40h
    ret
PrintUint64 endp

; ==============================================================================
; Data Section
; ==============================================================================
.data
epsilon real4 1.0e-6

end
