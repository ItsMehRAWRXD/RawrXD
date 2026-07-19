; Simple test benchmark
extrn GetStdHandle : proc
extrn WriteFile : proc
extrn ExitProcess : proc

STD_OUTPUT_HANDLE equ -11

.data
    hConsole      dq 0
    bytesWritten  dq 0
    msgTest       db "Deep2 Benchmark Test", 10, 13
    msgLen        equ $ - msgTest

.code
main proc
    sub rsp, 40h

    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hConsole, rax

    mov rcx, hConsole
    lea rdx, msgTest
    mov r8, msgLen
    lea r9, bytesWritten
    mov qword ptr [rsp+20h], 0
    call WriteFile

    xor rcx, rcx
    call ExitProcess
main endp
end
