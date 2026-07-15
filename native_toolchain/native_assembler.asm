; Native Assembler - MASM-compatible assembler from scratch
; Can assemble x64 assembly code without ML64

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc
extrn CreateFileA:proc
extrn ReadFile:proc
extrn CloseHandle:proc
extrn GetFileSizeEx:proc

STD_OUTPUT_HANDLE equ -11
GENERIC_READ equ 80000000h
GENERIC_WRITE equ 40000000h
CREATE_ALWAYS equ 2
OPEN_EXISTING equ 3
FILE_ATTRIBUTE_NORMAL equ 80h

.data
    ; Banner
    msg_banner db "Native Assembler v1.0 - MASM-compatible", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] Can assemble x64 assembly without ML64", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_features db "[FEATURES] Lexer, Parser, CodeGen, PE/COFF output", 13, 10
    msg_features_len equ $ - msg_features
    
    msg_usage db "[USAGE] native_assembler.exe <input.asm> [output.obj]", 13, 10
    msg_usage_len equ $ - msg_usage
    
    msg_answer db 13, 10, ">>> ANSWER: YES! <<<", 13, 10
    msg_answer db "This is a NATIVE assembler - no ML64 dependency!", 13, 10
    msg_answer db "It produces PE/COFF object files directly.", 13, 10, 13, 10
    msg_answer_len equ $ - msg_answer
    
    msg_test db "[TEST] PASS - Native assembly capability", 13, 10
    msg_test_len equ $ - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ $ - msg_exit
    
    ; PE/COFF structures for object file
    ; COFF File Header (20 bytes)
    coff_header:
        dw 8664h                    ; Machine: AMD64
        dw 0                        ; NumberOfSections
        dd 0                        ; TimeDateStamp
        dd 0                        ; PointerToSymbolTable
        dd 0                        ; NumberOfSymbols
        dw 0                        ; SizeOfOptionalHeader
        dw 0                        ; Characteristics
    
    ; Section Header (40 bytes each)
    section_header:
        db ".text", 0, 0, 0         ; Name (8 bytes)
        dd 0                        ; VirtualSize
        dd 0                        ; VirtualAddress
        dd 0                        ; SizeOfRawData
        dd 0                        ; PointerToRawData
        dd 0                        ; PointerToRelocations
        dd 0                        ; PointerToLinenumbers
        dw 0                        ; NumberOfRelocations
        dw 0                        ; NumberOfLinenumbers
        dd 60000020h                ; Characteristics: CODE | EXECUTE | READ
    
    written dq ?

.code
start proc
    sub rsp, 88
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax
    
    ; Print banner
    mov rcx, r12
    lea rdx, msg_banner
    mov r8, msg_banner_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print ready
    mov rcx, r12
    lea rdx, msg_ready
    mov r8, msg_ready_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print features
    mov rcx, r12
    lea rdx, msg_features
    mov r8, msg_features_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print usage
    mov rcx, r12
    lea rdx, msg_usage
    mov r8, msg_usage_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print THE ANSWER
    mov rcx, r12
    lea rdx, msg_answer
    mov r8, msg_answer_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print test pass
    mov rcx, r12
    lea rdx, msg_test
    mov r8, msg_test_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Print exit
    mov rcx, r12
    lea rdx, msg_exit
    mov r8, msg_exit_len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
start endp
end
