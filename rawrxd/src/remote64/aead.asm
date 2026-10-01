OPTION CASEMAP:NONE
include remote.inc
EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC
EXTERN BCryptSetProperty:PROC
EXTERN BCryptGetProperty:PROC
EXTERN BCryptGenerateSymmetricKey:PROC
EXTERN BCryptDestroyKey:PROC
EXTERN BCryptEncrypt:PROC
EXTERN BCryptDecrypt:PROC
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteAeadEncrypt,RemoteAeadDecrypt
PUBLIC RemoteAeadLastStep,RemoteAeadLastStatus
PUBLIC RemoteAeadEntryRsp,RemoteAeadReturnRsp,RemoteAeadCallCount
PUBLIC RemoteAeadEntryRcx,RemoteAeadEntryRdx,RemoteAeadEntryR8,RemoteAeadEntryR9
PUBLIC RemoteAeadSlot00,RemoteAeadSlot08,RemoteAeadSlot10,RemoteAeadSlot18
PUBLIC RemoteAeadSlot20,RemoteAeadSlot28,RemoteAeadSlot30,RemoteAeadSlot38
PUBLIC RemoteAeadSlot40,RemoteAeadSlot48,RemoteAeadSlot50
PUBLIC RemoteAeadDecOut,RemoteAeadDecOutCap,RemoteAeadDecTag
PUBLIC RemoteAeadDecAad,RemoteAeadDecAadLen
PUBLIC RemoteAeadWorkerProbe

.data
align 2
aesName     WORD 'A','E','S',0
; BUG 62.5: the property NAME and the property VALUE are distinct strings.
; Declaring L"ChainingMode" then L"GCM" separately set the invalid chaining
; mode "ChainingMode" and BCryptSetProperty failed.
modeName    WORD 'C','h','a','i','n','i','g','M','o','d','e',0
chainName   WORD 'C','h','a','i','n','i','n','g','M','o','d','e','G','C','M',0
objName     WORD 'O','b','j','e','c','t','L','e','n','g','t','h',0
; Measured failure locator.
RemoteAeadLastStep   DWORD 0
RemoteAeadLastStatus DWORD 0
; Entry/return markers, written by the worker itself so a probe can prove
; whether control actually reached the intended points.
RemoteAeadEntryRsp   QWORD 0
RemoteAeadReturnRsp  QWORD 0
RemoteAeadCallCount  DWORD 0
; Raw entry snapshot, captured at the worker's FIRST instruction before any
; push or sub rsp. A_WRAP_BASE was derived from the ABI text and proved wrong
; (identical calls were rejected for different reasons), so the layout is now
; measured instead of assumed.
RemoteAeadEntryRcx   QWORD 0
RemoteAeadEntryRdx   QWORD 0
RemoteAeadEntryR8    QWORD 0
RemoteAeadEntryR9    QWORD 0
RemoteAeadSlot00     QWORD 0
RemoteAeadSlot08     QWORD 0
RemoteAeadSlot10     QWORD 0
RemoteAeadSlot18     QWORD 0
RemoteAeadSlot20     QWORD 0
RemoteAeadSlot28     QWORD 0
RemoteAeadSlot30     QWORD 0
RemoteAeadSlot38     QWORD 0
RemoteAeadSlot40     QWORD 0
RemoteAeadSlot48     QWORD 0
RemoteAeadSlot50     QWORD 0
; What the worker actually decoded from the argument area.
RemoteAeadDecOut     QWORD 0
RemoteAeadDecOutCap  QWORD 0
RemoteAeadDecTag     QWORD 0
RemoteAeadDecAad     QWORD 0
RemoteAeadDecAadLen  QWORD 0

.code

; Local frame offsets. The first 060h bytes are the outbound call area for the
; widest callee (BCryptEncrypt/Decrypt, 10 parameters), so no saved local may
; live there.
P_OUT     EQU 060h
P_OUTCAP  EQU 068h
P_TAG     EQU 070h
P_AAD     EQU 078h
P_AADLEN  EQU 080h
P_ALG     EQU 090h
P_KEYH    EQU 098h
P_OBJ     EQU 0A0h
P_OBJLEN  EQU 0A8h
P_RESULT  EQU 0B0h
P_STEP    EQU 0B8h
P_STATUS  EQU 0BCh
P_INFO    EQU 0C0h

; Caller stack arguments, relative to the base the wrapper supplies in R10.
; A_WRAP_BASE is the RSP seen by a wrapper entered by CALL, which is also where
; AeadWorker's first stack argument lives under JMP entry. A_DIRECT_BASE
; compensates for the extra return address that the direct test entry pushes.
A_WRAP_BASE   EQU 028h
A_DIRECT_BASE EQU 020h

CHAINING_MODE_BYTES EQU 16
OBJECT_NAME_BYTES   EQU 13
NONCE_BYTES         EQU 12
TAG_BYTES           EQU 16
KEY_BYTES           EQU 32

AS_PRECHECK EQU 1
AS_OPEN     EQU 2
AS_MODE     EQU 3
AS_OBJLEN   EQU 4
AS_ALLOC    EQU 5
AS_KEY      EQU 6
AS_INFO     EQU 7
AS_CRYPT    EQU 8
AS_DONE     EQU 9

; ---------------------------------------------------------------------------
; AeadWorker
;   rcx  = 32-byte key
;   rdx  = 12-byte nonce
;   r8   = input
;   r9   = input length
;   r10  = base for the five stack arguments (see A_WRAP_BASE)
;   r12  = 0 encrypt, 1 decrypt
; ---------------------------------------------------------------------------
AeadWorker PROC
    ; =====================================================================
    ; RAW ENTRY CAPTURE - must remain the first code in this procedure.
    ; Runs before any push or sub rsp, so the slots are exactly what the
    ; entry mechanism presented. Nothing here may touch r10 (the argument
    ; base) or clobber rcx/rdx/r8/r9.
    ; =====================================================================
    inc DWORD PTR [RemoteAeadCallCount]
    mov [RemoteAeadEntryRsp],rsp
    mov [RemoteAeadEntryRcx],rcx
    mov [RemoteAeadEntryRdx],rdx
    mov [RemoteAeadEntryR8],r8
    mov [RemoteAeadEntryR9],r9
    mov rax,[rsp+00h]
    mov [RemoteAeadSlot00],rax
    mov rax,[rsp+08h]
    mov [RemoteAeadSlot08],rax
    mov rax,[rsp+10h]
    mov [RemoteAeadSlot10],rax
    mov rax,[rsp+18h]
    mov [RemoteAeadSlot18],rax
    mov rax,[rsp+20h]
    mov [RemoteAeadSlot20],rax
    mov rax,[rsp+28h]
    mov [RemoteAeadSlot28],rax
    mov rax,[rsp+30h]
    mov [RemoteAeadSlot30],rax
    mov rax,[rsp+38h]
    mov [RemoteAeadSlot38],rax
    mov rax,[rsp+40h]
    mov [RemoteAeadSlot40],rax
    mov rax,[rsp+48h]
    mov [RemoteAeadSlot48],rax
    mov rax,[rsp+50h]
    mov [RemoteAeadSlot50],rax

    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp,120h

    mov DWORD PTR [rsp+P_RESULT],0
    mov DWORD PTR [rsp+P_STEP],0
    mov DWORD PTR [rsp+P_STATUS],0
    mov QWORD PTR [rsp+P_ALG],0
    mov QWORD PTR [rsp+P_KEYH],0
    mov QWORD PTR [rsp+P_OBJ],0
    mov DWORD PTR [rsp+P_OBJLEN],0

    inc DWORD PTR [RemoteAeadCallCount]
    mov [RemoteAeadEntryRsp],rsp

    mov r13,rcx          ; key
    mov r14,rdx          ; nonce
    mov r15,r8           ; input
    mov rdi,r9           ; input length

    ; --- capture caller arguments before any call can clobber the frame ---
    mov rax,[r10+A_WRAP_BASE]
    mov [rsp+P_OUT],rax
    mov rax,[r10+A_WRAP_BASE+8]
    mov [rsp+P_OUTCAP],rax
    mov rax,[r10+A_WRAP_BASE+16]
    mov [rsp+P_TAG],rax
    mov rax,[r10+A_WRAP_BASE+24]
    mov [rsp+P_AAD],rax
    mov rax,[r10+A_WRAP_BASE+32]
    mov [rsp+P_AADLEN],rax

    ; publish what the worker decoded, for caller-side comparison
    mov rax,[rsp+P_OUT]
    mov [RemoteAeadDecOut],rax
    mov rax,[rsp+P_OUTCAP]
    mov [RemoteAeadDecOutCap],rax
    mov rax,[rsp+P_TAG]
    mov [RemoteAeadDecTag],rax
    mov rax,[rsp+P_AAD]
    mov [RemoteAeadDecAad],rax
    mov rax,[rsp+P_AADLEN]
    mov [RemoteAeadDecAadLen],rax

    ; --- pre-checks ---
    test rdi,rdi
    jz aw_skip_cap
    cmp rdi,[rsp+P_OUTCAP]
    ja aw_fail_cap
    test QWORD PTR [rsp+P_OUT],0
    jz aw_fail_out
aw_skip_cap:
    test QWORD PTR [rsp+P_TAG],0
    jz aw_fail_tag
    test QWORD PTR [rsp+P_AAD],0
    jz aw_fail_aad
    mov eax,[rsp+P_AADLEN]
    test eax,eax
    jz aw_fail_aadlen

    ; --- open AES provider ---
    lea rcx,[rsp+P_ALG]
    lea rdx,aesName
    xor r8d,r8d
    xor r9d,r9d
    call BCryptOpenAlgorithmProvider
    mov [rsp+P_STATUS],eax
    test eax,eax
    js aw_fail_open
    mov DWORD PTR [rsp+P_STEP],AS_OPEN

    ; --- ChainingMode ---
    mov DWORD PTR [rsp+P_STEP],AS_MODE
    mov rcx,[rsp+P_ALG]
    lea rdx,modeName
    lea r8,chainName
    mov r9d,CHAINING_MODE_BYTES
    mov DWORD PTR [rsp+20h],0
    call BCryptSetProperty
    mov [rsp+P_STATUS],eax
    test eax,eax
    js aw_close

    ; --- ObjectLength ---
    mov DWORD PTR [rsp+P_STEP],AS_OBJLEN
    mov DWORD PTR [rsp+P_OBJLEN],0
    lea rax,[rsp+P_RESULT]
    mov rcx,[rsp+P_ALG]
    lea rdx,objName
    lea r8,[rsp+P_OBJLEN]
    mov r9d,4
    mov [rsp+20h],rax
    mov DWORD PTR [rsp+28h],0
    call BCryptGetProperty
    mov [rsp+P_STATUS],eax
    test eax,eax
    js aw_close

    ; --- key object ---
    mov DWORD PTR [rsp+P_STEP],AS_ALLOC
    mov ecx,[rsp+P_OBJLEN]
    test ecx,ecx
    jz aw_close
    call RemoteAlloc
    test rax,rax
    jz aw_close
    mov [rsp+P_OBJ],rax

    mov DWORD PTR [rsp+P_STEP],AS_KEY
    mov rcx,[rsp+P_ALG]
    lea rdx,[rsp+P_KEYH]
    mov r8,[rsp+P_OBJ]
    mov r9d,[rsp+P_OBJLEN]
    mov QWORD PTR [rsp+20h],r13
    mov DWORD PTR [rsp+28h],KEY_BYTES
    mov DWORD PTR [rsp+30h],0
    call BCryptGenerateSymmetricKey
    mov [rsp+P_STATUS],eax
    test eax,eax
    js aw_free

    ; --- authenticated cipher mode info ---
    mov DWORD PTR [rsp+P_STEP],AS_INFO
    lea rsi,[rsp+P_INFO]
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.cbSize,SIZEOF BCRYPT_AEAD_INFO
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.dwInfoVersion,1
    mov [rsi].BCRYPT_AEAD_INFO.pbNonce,r14
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.cbNonce,NONCE_BYTES
    mov [rsi].BCRYPT_AEAD_INFO.pbAuthData,0
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.cbAuthData,0
    mov rax,[rsp+P_TAG]
    mov [rsi].BCRYPT_AEAD_INFO.pbTag,rax
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.cbTag,TAG_BYTES
    mov [rsi].BCRYPT_AEAD_INFO.pbMacContext,0
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.cbMacContext,0
    mov eax,[rsp+P_AADLEN]
    mov [rsi].BCRYPT_AEAD_INFO.cbAAD,eax
    mov rax,[rsp+P_AAD]
    mov [rsi].BCRYPT_AEAD_INFO.pbAAD,rax
    mov [rsi].BCRYPT_AEAD_INFO.cbData,edi
    mov DWORD PTR [rsi].BCRYPT_AEAD_INFO.dwFlags,0

    ; --- BCryptEncrypt / BCryptDecrypt ---
    mov DWORD PTR [rsp+P_STEP],AS_CRYPT
    mov rcx,[rsp+P_KEYH]
    mov rdx,r15
    mov r8d,edi
    mov r9,rsi
    mov QWORD PTR [rsp+20h],0
    mov DWORD PTR [rsp+28h],0
    mov rax,[rsp+P_OUT]
    mov [rsp+30h],rax
    mov rax,[rsp+P_OUTCAP]
    mov [rsp+38h],rax
    lea rax,[rsp+P_RESULT]
    mov [rsp+40h],rax
    mov DWORD PTR [rsp+48h],0
    cmp r12d,0
    jne aw_dec
    call BCryptEncrypt
    jmp aw_after
aw_dec:
    call BCryptDecrypt
aw_after:
    mov [rsp+P_STATUS],eax

    mov rcx,[rsp+P_KEYH]
    call BCryptDestroyKey
aw_free:
    mov rcx,[rsp+P_OBJ]
    call RemoteFree
aw_close:
    mov rcx,[rsp+P_ALG]
    xor edx,edx
    call BCryptCloseAlgorithmProvider
    mov eax,[rsp+P_STATUS]
    test eax,eax
    jnz aw_done
    mov DWORD PTR [rsp+P_STEP],AS_DONE
    mov eax,[rsp+P_RESULT]      ; success returns the produced byte count
    jmp aw_done
aw_fail_cap:
    mov DWORD PTR [rsp+P_STEP],AS_PRECHECK+10
    jmp aw_fail_pre
aw_fail_out:
    mov DWORD PTR [rsp+P_STEP],AS_PRECHECK+20
    jmp aw_fail_pre
aw_fail_tag:
    mov DWORD PTR [rsp+P_STEP],AS_PRECHECK+30
    jmp aw_fail_pre
aw_fail_aad:
    mov DWORD PTR [rsp+P_STEP],AS_PRECHECK+40
    jmp aw_fail_pre
aw_fail_aadlen:
    mov DWORD PTR [rsp+P_STEP],AS_PRECHECK+50
    jmp aw_fail_pre
aw_fail_pre:
    mov DWORD PTR [rsp+P_STATUS],0C000000Dh  ; STATUS_INVALID_PARAMETER
    mov eax,[rsp+P_STATUS]
    jmp aw_done
aw_fail_open:
    mov DWORD PTR [rsp+P_STEP],AS_OPEN
    mov eax,[rsp+P_STATUS]
    jmp aw_done
aw_done:
    mov ecx,[rsp+P_STEP]
    mov RemoteAeadLastStep,ecx
    mov ecx,[rsp+P_STATUS]
    mov RemoteAeadLastStatus,ecx
    mov [RemoteAeadReturnRsp],rsp
    add rsp,120h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
AeadWorker ENDP

; Production entry: JMP into the worker. R10 is the wrapper's own RSP, which is
; where the first stack argument lives.
RemoteAeadEncrypt PROC
    xor r12d,r12d
    mov r10,rsp
    jmp AeadWorker
RemoteAeadEncrypt ENDP

RemoteAeadDecrypt PROC
    mov r12d,1
    mov r10,rsp
    jmp AeadWorker
RemoteAeadDecrypt ENDP

; Diagnostic entry: conventional CALL. The pushed return address shifts the
; worker's view of the stack, so R10 is biased by A_DIRECT_BASE to point at the
; same argument slots the JMP path sees. Used only by the isolation probe.
RemoteAeadWorkerProbe PROC
    ; rcx = mode (0 encrypt, 1 decrypt); all other args identical to the
    ; public entry points.
    mov r12d,ecx
    mov r10,rsp
    add r10,A_DIRECT_BASE
    call AeadWorker
    ret
RemoteAeadWorkerProbe ENDP
END
