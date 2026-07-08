; test_data_rip.asm
; Test RIP-relative addressing for data section access
; This is how x64 Windows accesses global variables

.data
    ; Global variables
    global_counter dq 0
    global_msg db "Hello from data section!", 0
    global_value dd 42

.text
main:
    ; Standard prologue
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Test 1: Load address of global using LEA (RIP-relative)
    lea rcx, [global_msg]
    
    ; Test 2: Read global value using RIP-relative addressing
    mov eax, [global_value]
    
    ; Test 3: Increment global counter
    mov rcx, [global_counter]
    add rcx, 1
    mov [global_counter], rcx
    
    ; Test 4: Call ExitProcess with the counter value as exit code
    mov ecx, eax
    call ExitProcess

    mov ecx, eax
    call ExitProcess
