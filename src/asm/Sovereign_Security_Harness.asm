; ==================================================================================
; SOVEREIGN CONFIGURATION SUBSTRATE - SECURITY VERIFICATION HARNESS
; File: Sovereign_Security_Harness.asm
; ==================================================================================
.code

; --- EXTERNAL REFERENCES TO SUBSTRATE LOGIC ---
EXTERN Sovereign_Get_Hardware_ID : PROC
EXTERN Sovereign_Verify_License  : PROC
EXTERN Sovereign_Generate_Key     : PROC

;-----------------------------------------------------------------------------------
; Verification Subsystem Smoketest Console Entry Point
; Returns 0 on success, or non-zero exit status if mathematical mismatch occurs
;-----------------------------------------------------------------------------------
main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 80     ; Frame buffer allocations for stack protection metrics
    
    ; Step 1: Capture direct HWID validation signature
    call Sovereign_Get_Hardware_ID
    mov r8, rax     ; Cache hardware tracking id in R8
    
    ; Step 2: Establish mock configurations (Pro/Enterprise/800B/Swarm)
    mov r9, 0x0000001E
    
    ; Step 3: Compute key signature utilizing isolation criteria
    mov rcx, r8
    mov rdx, r9
    call Sovereign_Generate_Key
    mov r10, rax    ; Cache calculated signature sequence
    
    ; Step 4: Populate local stack verification structure instance
    ; Memory layout construction mimics aligned structurally strict struct models
    mov [rsp + 0],  r8   ; HardwareID Offset
    mov [rsp + 8],  r9   ; FeatureMask Offset
    mov [rsp + 16], r10  ; Signature Offset
    mov qword ptr [rsp + 24], 0 ; Clear explicit Expiry field metrics
    
    ; Step 5: Route structure back to complete full verification loop test
    lea rcx, [rsp + 0]
    call Sovereign_Verify_License
    
    ; Step 6: Map boolean status to explicit return metrics
    test rax, rax
    jz @HarnessFailure
    
    ; Case A: Validation Passed perfectly
    xor eax, eax    ; Exit code 0
    jmp @HarnessExit

@HarnessFailure:
    ; Case B: Validation failure detected within layout matrix
    mov eax, 1      ; Exit code 1

@HarnessExit:
    mov rsp, rbp
    pop rbp
    ret
main ENDP

END
