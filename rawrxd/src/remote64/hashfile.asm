OPTION CASEMAP:NONE
include remote.inc
EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC
EXTERN BCryptGetProperty:PROC
EXTERN BCryptCreateHash:PROC
EXTERN BCryptHashData:PROC
EXTERN BCryptFinishHash:PROC
EXTERN BCryptDestroyHash:PROC
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteHash_BufferSha256
PUBLIC RemoteHashLastStep
PUBLIC RemoteHashLastStatus

; Measured failure locator. The previous version returned an NTSTATUS that did
; not correspond to any documented failure code, because dwFlags for
; BCryptCreateHash was left uninitialized. The step/status pair makes the next
; failure self-diagnosing instead of guesswork.
.data
RemoteHashLastStep   DWORD 0
RemoteHashLastStatus DWORD 0
sha256Name dw 'S','A','H','2','5','6',0
objLenName dw 'O','b','j','e','c','t','L','e','n','g','t','h',0

.code
; step codes
HS_IDLE       EQU 0
HS_OPEN_ALG   EQU 1
HS_GET_OBJLEN EQU 2
HS_ALLOC      EQU 3
HS_CREATE     EQU 4
HS_DATA       EQU 5
HS_FINISH     EQU 6

; Frame layout. The first 040h bytes are the outgoing argument area for the
; widest callee (BCryptCreateHash, 7 parameters), so no saved local may live
; there. The previous version stored the algorithm handle at [rsp+30h], which
; is exactly where BCryptCreateHash reads dwFlags from.
H_ALG    EQU 040h
H_HASH   EQU 048h
H_OBJLEN EQU 050h
H_OBJ    EQU 058h
H_STEP   EQU 060h
H_STATUS EQU 064h
H_PCB    EQU 068h

RemoteHash_BufferSha256 PROC
    ; rcx=data rdx=len r8=32-byte output; NTSTATUS in eax
    push rbx
    push rsi
    push rdi
    sub rsp,70h
    mov rsi,rcx
    mov edi,edx
    mov rbx,r8

    mov QWORD PTR [rsp+H_ALG],0
    mov QWORD PTR [rsp+H_HASH],0
    mov QWORD PTR [rsp+H_OBJ],0
    mov DWORD PTR [rsp+H_OBJLEN],0

    lea rcx,[rsp+H_ALG]
    lea rdx,sha256Name
    xor r8d,r8d
    xor r9d,r9d
    call BCryptOpenAlgorithmProvider
    mov [rsp+H_STATUS],eax
    test eax,eax
    jl hs_fail_open
    mov DWORD PTR [rsp+H_STEP],HS_OPEN_ALG

    ; ObjectLength
    ; BUG 63.1: pcbResult used to point at H_STEP, so the returned size
    ; overwrote the failure-stage marker and made the reported step garbage.
    lea rax,[rsp+H_PCB]
    mov rcx,[rsp+H_ALG]
    lea rdx,objLenName
    lea r8,[rsp+H_OBJLEN]
    mov r9d,4
    mov [rsp+20h],rax
    mov DWORD PTR [rsp+28h],0
    call BCryptGetProperty
    mov [rsp+H_STATUS],eax
    test eax,eax
    jl hs_close
    mov DWORD PTR [rsp+H_STEP],HS_GET_OBJLEN

    mov ecx,[rsp+H_OBJLEN]
    test ecx,ecx
    jz hs_status_invalid
    call RemoteAlloc
    test rax,rax
    jz hs_close
    mov [rsp+H_OBJ],rax
    mov DWORD PTR [rsp+H_STEP],HS_ALLOC

    ; BCryptCreateHash(hAlgorithm, phHash, pbHashObject, cbHashObject,
    ;                  pbSecret, cbSecret, dwFlags)
    mov rcx,[rsp+H_ALG]
    lea rdx,[rsp+H_HASH]
    mov r8,[rsp+H_OBJ]
    mov r9d,[rsp+H_OBJLEN]
    mov QWORD PTR [rsp+20h],0          ; pbSecret
    mov DWORD PTR [rsp+28h],0          ; cbSecret
    mov DWORD PTR [rsp+30h],0          ; dwFlags
    call BCryptCreateHash
    mov [rsp+H_STATUS],eax
    test eax,eax
    jl hs_free
    mov DWORD PTR [rsp+H_STEP],HS_CREATE

    mov rcx,[rsp+H_HASH]
    mov rdx,rsi
    mov r8d,edi
    xor r9d,r9d
    call BCryptHashData
    mov [rsp+H_STATUS],eax
    test eax,eax
    jl hs_destroy
    mov DWORD PTR [rsp+H_STEP],HS_DATA

    mov rcx,[rsp+H_HASH]
    mov rdx,rbx
    mov r8d,32
    xor r9d,r9d
    call BCryptFinishHash
    mov [rsp+H_STATUS],eax
    test eax,eax
    jl hs_destroy
    mov DWORD PTR [rsp+H_STEP],HS_FINISH

hs_destroy:
    mov rcx,[rsp+H_HASH]
    call BCryptDestroyHash
hs_free:
    mov rcx,[rsp+H_OBJ]
    call RemoteFree
hs_close:
    mov rcx,[rsp+H_ALG]
    xor edx,edx
    call BCryptCloseAlgorithmProvider
    mov eax,[rsp+H_STATUS]
    jmp hs_done

hs_status_invalid:
    mov DWORD PTR [rsp+H_STATUS],0C000000Dh   ; STATUS_INVALID_PARAMETER
hs_fail_open:
    mov eax,[rsp+H_STATUS]

hs_done:
    mov ecx,[rsp+H_STEP]
    mov RemoteHashLastStep,ecx
    mov ecx,[rsp+H_STATUS]
    mov RemoteHashLastStatus,ecx
    add rsp,70h
    pop rdi
    pop rsi
    pop rbx
    ret
RemoteHash_BufferSha256 ENDP
END
