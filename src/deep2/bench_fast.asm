; Fast Deep2 Benchmark - Reduced iterations for quick results
extrn GetStdHandle : proc
extrn WriteFile : proc
extrn VirtualAlloc : proc
extrn VirtualFree : proc
extrn QueryPerformanceFrequency : proc
extrn QueryPerformanceCounter : proc
extrn ExitProcess : proc
extrn Deep2_VecDotProduct : proc

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
    resultBuffer  dd 0
    
    msgStart      db "Deep2 VecDotProduct Benchmark", 10, 13
    msgStartLen   equ $ - msgStart
    msgTicks      db "Ticks: ", 0
    msgTicksLen   equ $ - msgTicks
    newline       db 10, 13
    
    numBuffer     db 32 dup(0)

.code
main proc
    sub rsp, 40h

    ; Get stdout
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hConsole, rax

    ; Print start
    mov rcx, hConsole
    lea rdx, msgStart
    mov r8, msgStartLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Get QPF
    lea rcx, qpf
    call QueryPerformanceFrequency

    ; Allocate small buffer (1MB)
    xor rcx, rcx
    mov rdx, 1024*1024
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    mov r12, rax

    xor rcx, rcx
    mov rdx, 1024*1024
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    mov r13, rax

    ; Init with 1.0f
    mov rdi, r12
    mov ecx, 256*1024
    mov eax, 03f800000h
@@init:
    mov dword ptr [rdi], eax
    add rdi, 4
    dec ecx
    jnz @@init

    mov rdi, r13
    mov ecx, 256*1024
@@init2:
    mov dword ptr [rdi], eax
    add rdi, 4
    dec ecx
    jnz @@init2

    ; Start timer
    lea rcx, qpcStart
    call QueryPerformanceCounter

    ; Run 100 iterations
    mov r14, 100
@@loop:
    mov rcx, r12
    mov rdx, r13
    lea r8, resultBuffer
    mov r9, 256*1024
    call Deep2_VecDotProduct
    dec r14
    jnz @@loop

    ; End timer
    lea rcx, qpcEnd
    call QueryPerformanceCounter

    ; Print ticks
    mov rcx, hConsole
    lea rdx, msgTicks
    mov r8, msgTicksLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Calc and print elapsed
    mov rax, qpcEnd
    sub rax, qpcStart
    call PrintNumber

    ; Newline
    mov rcx, hConsole
    lea rdx, newline
    mov r8, 2
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    ; Cleanup
    mov rcx, r12
    xor rdx, rdx
    mov r8, MEM_RELEASE
    call VirtualFree
    mov rcx, r13
    xor rdx, rdx
    mov r8, MEM_RELEASE
    call VirtualFree

    xor rcx, rcx
    call ExitProcess
main endp

PrintNumber proc
    sub rsp, 40h
    lea rdi, numBuffer
    add rdi, 31
    mov byte ptr [rdi], 0
    mov rbx, 10
@@conv:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz @@conv

    lea rax, numBuffer
    add rax, 31
    sub rax, rdi
    mov r8, rax

    mov rcx, hConsole
    mov rdx, rdi
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 40h
    ret
PrintNumber endp
end
