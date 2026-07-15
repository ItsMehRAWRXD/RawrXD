; Test MASM x64 program with imports
; Tests the native linker's import table generation

option casemap:none

; External functions - these should be resolved via import table
extern GetModuleHandleA : proc
extern MessageBoxA : proc
extern ExitProcess : proc

; Data section
.data
    caption db "Import Test", 0
    message db "Hello from import table!", 0
    modName db "kernel32.dll", 0

; Code section
.code
main proc
    sub rsp, 28h        ; Shadow space + alignment
    
    ; Test GetModuleHandleA
    lea rcx, modName
    call GetModuleHandleA
    
    ; Test MessageBoxA
    xor rcx, rcx        ; hWnd = NULL
    lea rdx, message    ; lpText
    lea r8, caption     ; lpCaption
    xor r9, r9          ; uType = MB_OK
    call MessageBoxA
    
    ; Exit
    xor rcx, rcx
    call ExitProcess
    
    add rsp, 28h
    ret
main endp

end