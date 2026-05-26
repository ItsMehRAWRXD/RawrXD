; Sovereign_Build_Gate.asm - Pre-flight verification logic
; ABI: Standard Win64 Entry
; Purpose: Pipeline-integrated validation gate for Sovereign OS

.CODE

; XR_Build_Gate: Executed by build_pipeline.bat post-link
; RCX = ManifestPtr, RDX = NodeCount
PUBLIC XR_Build_Gate
XR_Build_Gate PROC
    sub rsp, 40
    
    ; 1. Perform Integrity Check
    call XR_Test_Integrity
    
    ; 2. Branch on status
    mov rcx, 0CAFEBABEh
    cmp rax, rcx
    je build_success
    
    ; 3. Pipeline Failure Trigger
    mov ecx, 1                  ; Exit Code 1
    call ExitProcess            ; Hard-stop build
    
build_success:
    xor rax, rax                ; Return 0
    add rsp, 40
    ret
XR_Build_Gate ENDP

EXTERN ExitProcess : PROC
EXTERN XR_Test_Integrity : PROC

END
