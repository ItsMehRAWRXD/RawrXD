; ==============================================================================
; Sovereign_Main.asm - Elite Production Orchestrator
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

; --- Externals ---
EXTERN Sovereign_PEB_Loader      : PROC
EXTERN Sovereign_Heap_Init        : PROC
EXTERN Sovereign_LoadModel_Disk  : PROC
EXTERN Sovereign_ScanPattern      : PROC
EXTERN Sovereign_Hardware_Audit   : PROC
EXTERN g_SovereignHub            : SovereignHub

; --- Global Data (Externals from Globals.obj) ---
EXTERN g_ApiTable : SOVEREIGN_API_TABLE
EXTERN g_pGov     : QWORD
EXTERN g_HeapBase : QWORD
EXTERN g_HeapPtr  : QWORD
EXTERN g_HeapLimit : QWORD

.DATA
szModelPath DB "D:\codestral22b.gguf", 0
szMsgInit   DB "[ELITE] Sovereign Production Orchestrator: Multi-Module Mode ACTIVE.", 10, 0
szMsgLoad   DB "[ELITE] Mapping Model: D:\codestral22b.gguf", 10, 0
szMsgScan   DB "[ELITE] SIMD Scanner: Commencing Hardware Audit...", 10, 0
szMsgTensorFound DB "[ELITE] Model Loader: Tensor Index Built Successfully.", 10, 0
szMsgLoadRet DB "[ELITE] Model Loader Returned.", 10, 0
szMsgSuccess DB "[ELITE] Sovereign Execution Complete. Check Output Logs.", 10, 0
szMsgMagic    DB "[PHASE1] magic=0x",0
szMsgVersion  DB " version=",0
szMsgTcount   DB " tensors=",0
szMsgKVcount  DB " kv=",0
szNewline     DB 10,0
szErrPrefix   DB "[ERR] LoadModel rc=",0
hexDigits     DB "0123456789ABCDEF"
hexBuf        DB 20 DUP(0)
decBuf        DB 24 DUP(0)
szTocHdr      DB "[PHASE2] Tensor TOC (first 5):", 10, 0
szTocSep      DB "  ", 0
szTocArrow    DB " -> ", 0
szTocType     DB " type=", 0
szTocNdim     DB " ndim=", 0
szTocNe       DB " ne=[", 0
szTocNeSep    DB ",", 0
szTocNeEnd    DB "]", 0
szTocHash     DB " hash=0x", 0
szTocPtr      DB " pData=0x", 0
szDiagPIdx    DB "[DIAG] pIndex=0x", 0
szDiagSize    DB " sizeof(TENSOR_INFO)=", 0
szDiagRaw0    DB "[DIAG] pIndex[0]=0x", 0
szDiagHB      DB "[DIAG] g_HeapBase=0x", 0
szDiagHP      DB " g_HeapPtr=0x", 0
szDiagMod     DB " &model=0x", 0
szDiagLdr1    DB "[DIAG] loader_r13=0x", 0
szDiagLdr2    DB " pIdxFieldAddr=0x", 0
szDiagLdr3    DB "[DIAG] mallocRet=0x", 0
szDiagLdr4    DB " pIdxReadbackInLoader=0x", 0
szDiagRsiHdr  DB "[DIAG] rsi-before-loop=0x", 0
szDiagRawHdr  DB "[DIAG] heap[0..88]: ", 0

.CODE

; ----------------------------------------------------------------------------
; mainCRTStartup
; Bare-metal entry point.
; ----------------------------------------------------------------------------
PUBLIC mainCRTStartup
mainCRTStartup PROC
    and rsp, -16            ; force 16-byte alignment
    sub rsp, 40             ; Shadow space + alignment

    ; 1. Resolve APIs (Zero-IAT)
    call Sovereign_PEB_Loader
    cmp [g_ApiTable.pWriteFile], 0
    jz @@FatalExit
    
    ; 2. Bootstrap Core Engine (Hidden Entry)
    EXTERN Sovereign_Bootstrap_Core : PROC
    call Sovereign_Bootstrap_Core

    ; 3. Initialize Subsystems (Heap)
    call Sovereign_Heap_Init
    test rax, rax
    jz @@FatalExit

    ; 4. Hardware Audit (Dispatcher Setup)
    call Sovereign_Hardware_Audit

    ; 5. Setup Governance State
    lea rax, static_gov
    mov [g_pGov], rax
    lea rdx, static_model
    mov [rax].GOV_STATE.pModelState, rdx

    ; 6. Banner Output
    lea rcx, szMsgInit
    call Print

    ; 7. Load Real Model (D:\codestral22b.gguf)
    lea rcx, szMsgLoad
    call Print
    
    lea rcx, szModelPath
    call Sovereign_LoadModel_Disk
    test rax, rax
    jnz @@Error ; jnz because 0 is success

    ; 7.5. Verify Index
    mov r12, [g_pGov]
    mov r13, [r12].GOV_STATE.pModelState

    ; Phase 1 dump: magic / version / tensor_count / kv_count
    lea rcx, szMsgMagic
    call Print
    mov eax, GGUF_MAGIC
    mov rcx, rax
    call PrintHex32
    lea rcx, szMsgVersion
    call Print
    mov eax, [r13].MODEL_STATE.version
    mov rcx, rax
    call PrintDec64
    lea rcx, szMsgTcount
    call Print
    mov rcx, [r13].MODEL_STATE.tensor_count
    call PrintDec64
    lea rcx, szMsgKVcount
    call Print
    mov rcx, [r13].MODEL_STATE.metadata_kv_count
    call PrintDec64
    lea rcx, szNewline
    call Print

    mov rax, [r13].MODEL_STATE.tensor_count
    test rax, rax
    jz @@SkipPrint
    lea rcx, szMsgTensorFound
    call Print

    ; Phase 2: Dump first 5 entries of resolved tensor TOC
    lea rcx, szTocHdr
    call Print
    mov rsi, [r13].MODEL_STATE.pIndex
    test rsi, rsi
    jz @@SkipPrint

    ; Diag (single line): print pIndex address (heap pointer to TENSOR_INFO[0])
    lea rcx, szDiagPIdx
    call Print
    mov rcx, [r13].MODEL_STATE.pIndex
    call PrintHex64
    lea rcx, szNewline
    call Print
    lea rcx, szNewline
    call Print

    ; --- Loader stash diagnostics ---
    lea rcx, szDiagLdr1
    call Print
    mov rcx, [g_DbgLoaderR13]
    call PrintHex64
    lea rcx, szDiagLdr2
    call Print
    mov rcx, [g_DbgPIdxFieldAddr]
    call PrintHex64
    lea rcx, szNewline
    call Print
    lea rcx, szDiagLdr3
    call Print
    mov rcx, [g_DbgMallocRet]
    call PrintHex64
    lea rcx, szDiagLdr4
    call Print
    mov rcx, [g_DbgPIdxReadback]
    call PrintHex64
    lea rcx, szNewline
    call Print

    ; --- RAW heap dump: first TENSOR_INFO entry (88 bytes as 11 qwords) ---
    mov r14, [r13].MODEL_STATE.pIndex
    mov [g_DbgTocPIdx], r14       ; persist pIndex into .DATA so loop is immune to register churn
    lea rcx, szDiagRawHdr
    call Print
    xor r15, r15
@@RawDmp:
    cmp r15, 11
    jae @@RawDmpDone
    mov rcx, [r14 + r15*8]
    call PrintHex64
    lea rcx, szTocSep
    call Print
    inc r15
    jmp @@RawDmp
@@RawDmpDone:
    lea rcx, szNewline
    call Print

    mov rbx, [r13].MODEL_STATE.tensor_count
    cmp rbx, 5
    jbe @@TocCntOk
    mov rbx, 5
@@TocCntOk:
    ; Load rsi from the persisted .DATA slot — totally immune to register churn.
    mov rsi, [g_DbgTocPIdx]

    ; DIAG: dump rsi value right before loop entry
    lea rcx, szDiagRsiHdr
    call Print
    mov rcx, rsi
    call PrintHex64
    lea rcx, szNewline
    call Print
@@TocLoop:
    test rbx, rbx
    jz @@SkipPrint
    lea rcx, szTocSep
    call Print
    mov rcx, [rsi].TENSOR_INFO.pName
    mov rdx, [rsi].TENSOR_INFO.name_len
    call PrintRaw
    lea rcx, szTocType
    call Print
    mov ecx, [rsi].TENSOR_INFO.tensor_type
    mov ecx, ecx
    call PrintDec64
    lea rcx, szTocNdim
    call Print
    mov ecx, [rsi].TENSOR_INFO.n_dims
    mov ecx, ecx
    call PrintDec64
    lea rcx, szTocNe
    call Print
    mov rcx, [rsi].TENSOR_INFO.tensor_ne[0]
    call PrintDec64
    lea rcx, szTocNeSep
    call Print
    mov rcx, [rsi].TENSOR_INFO.tensor_ne[8]
    call PrintDec64
    lea rcx, szTocNeEnd
    call Print
    lea rcx, szTocHash
    call Print
    mov rcx, [rsi].TENSOR_INFO.name_hash
    call PrintHex64
    lea rcx, szTocPtr
    call Print
    mov rcx, [rsi].TENSOR_INFO.pData
    call PrintHex64
    lea rcx, szNewline
    call Print
    add rsi, SIZE TENSOR_INFO
    dec rbx
    jmp @@TocLoop
@@SkipPrint:

    ; 8. SIMD Scan
    lea rcx, szMsgScan
    call Print
    
    mov r12, [g_pGov]
    mov r13, [r12].GOV_STATE.pModelState
    mov rcx, [r13].MODEL_STATE.pWeightBase
    mov rdx, [r13].MODEL_STATE.weight_size
    lea r8, [szModelPath] ; Dummy pattern
    mov r9, 4             ; Length
    call Sovereign_ScanPattern

    ; 9. Final Success
    mov ecx, 'Y'
    call Probe
    lea rcx, szMsgSuccess
    call Print

    mov ecx, 'X'
    call Probe

    ; Diagnostic: is pExitProcess resolved?
    mov rax, [g_ApiTable.pExitProcess]
    test rax, rax
    jnz @@HaveExit
    mov ecx, '!'
    call Probe
    jmp @@Halt
@@HaveExit:
    mov ecx, '#'
    call Probe

    ; Realign stack to 16-byte boundary before calling ExitProcess (modern
    ; OS kernel uses aligned XMM ops in its prologue and AVs on misalignment).
    sub rsp, 8
    xor rcx, rcx
    call [g_ApiTable.pExitProcess]

@@Error:
    mov r15, rax            ; preserve rc
    lea rcx, szErrPrefix
    call Print
    mov rcx, r15
    call PrintDec64
    lea rcx, szNewline
    call Print
    mov rcx, r15
    call [g_ApiTable.pExitProcess]

@@FatalExit:
    mov rcx, -1
    mov rax, [g_ApiTable.pExitProcess]
    test rax, rax
    jz @@Halt
    call rax
@@Halt:
    hlt
mainCRTStartup ENDP

; ----------------------------------------------------------------------------
; Helper: Print String (ASCII) using Resolved WriteFile
; ----------------------------------------------------------------------------
Print PROC
    push rbp
    mov rbp, rsp
    push rsi                ; [rbp-8]  = saved rsi (above shadow region)
    push rdi                ; [rbp-16] = saved rdi
    sub rsp, 80             ; locals: [rbp-24..rbp-96); shadow lives at [rsp..rsp+32)

    mov [rbp-24], rcx       ; Save string ptr
    
    ; 1. Get StdHandle
    mov rcx, -11            ; STD_OUTPUT_HANDLE
    call [g_ApiTable.pGetStdHandle]
    mov [rbp-32], rax       ; Save hStdOut
    
    ; 2. Get Length
    mov rsi, [rbp-24]
    xor rax, rax
@@LenLoop:
    cmp byte ptr [rsi + rax], 0
    je @@LenDone
    inc rax
    jmp @@LenLoop
@@LenDone:
    mov r8, rax             ; R8 = Length
    
    ; 3. WriteFile
    mov rcx, [rbp-32]       ; hStdOut
    mov rdx, [rbp-24]       ; pBuffer
    ; R8 = Length (already set)
    lea r9, [rbp-40]        ; lpNumberOfBytesWritten
    mov qword ptr [rsp+32], 0 ; lpOverlapped
    call [g_ApiTable.pWriteFile]

    add rsp, 80
    pop rdi
    pop rsi
    leave
    ret
Print ENDP

; ----------------------------------------------------------------------------
; Probe: Write a single ASCII character (in CL) followed by newline to stdout
; ----------------------------------------------------------------------------
PUBLIC Probe
Probe PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    ; Stack layout (rsp=rbp-64):
    ;   [rbp-64..rbp-32) = shadow for callees
    ;   [rbp-32..rbp-24) = 5th arg slot ([rsp+32])
    ;   [rbp-24..rbp-16) = bytes_written out
    ;   [rbp-16..rbp-14) = 2-byte print buffer (char + '\n')
    ;   [rbp-8 ..rbp  ) = saved handle
    mov byte ptr [rbp-16], cl
    mov byte ptr [rbp-15], 10
    mov rcx, -11
    call [g_ApiTable.pGetStdHandle]
    mov [rbp-8], rax
    mov rcx, rax
    lea rdx, [rbp-16]
    mov r8d, 2
    lea r9, [rbp-24]
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pWriteFile]
    leave
    ret
Probe ENDP

; ----------------------------------------------------------------------------
; PrintHex32 - prints low 32 bits of RCX as 8 hex chars (no newline)
; ----------------------------------------------------------------------------
PrintHex32 PROC
    push rbp
    mov rbp, rsp
    push rbx                ; [rbp-8]
    push rsi                ; [rbp-16]
    push rdi                ; [rbp-24]
    sub rsp, 56             ; locals at [rbp-32..rbp-80); shadow at [rsp..rsp+32)
    mov rbx, rcx                ; value
    lea rdi, hexBuf
    mov rcx, 8
    lea rsi, hexDigits
@@phx_loop:
    mov rax, rbx
    shr rax, 28
    and rax, 0Fh
    mov al, [rsi + rax]
    mov [rdi], al
    inc rdi
    shl rbx, 4
    dec rcx
    jnz @@phx_loop
    mov byte ptr [rdi], 0
    mov rcx, -11
    call [g_ApiTable.pGetStdHandle]
    mov rcx, rax
    lea rdx, hexBuf
    mov r8d, 8
    lea r9, [rbp-32]
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pWriteFile]
    add rsp, 56
    pop rdi
    pop rsi
    pop rbx
    leave
    ret
PrintHex32 ENDP

; ----------------------------------------------------------------------------
; PrintDec64 - prints RCX as unsigned decimal (no newline)
; ----------------------------------------------------------------------------
PrintDec64 PROC
    push rbp
    mov rbp, rsp
    push rbx                ; [rbp-8]
    push rsi                ; [rbp-16]
    push rdi                ; [rbp-24]
    sub rsp, 56             ; locals at [rbp-32..rbp-80); shadow at [rsp..rsp+32)
    mov rax, rcx
    lea rdi, decBuf
    add rdi, 23                 ; end of buffer
    mov byte ptr [rdi], 0
    mov rbx, 10
    test rax, rax
    jnz @@pd_loop
    dec rdi
    mov byte ptr [rdi], '0'
    jmp @@pd_emit
@@pd_loop:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz @@pd_loop
@@pd_emit:
    ; length = (decBuf+23) - rdi
    lea rax, decBuf
    add rax, 23
    sub rax, rdi
    mov r10, rax                ; length
    mov rcx, -11
    call [g_ApiTable.pGetStdHandle]
    mov rcx, rax
    mov rdx, rdi
    mov r8, r10
    lea r9, [rbp-32]
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pWriteFile]
    add rsp, 56
    pop rdi
    pop rsi
    pop rbx
    leave
    ret
PrintDec64 ENDP

; ----------------------------------------------------------------------------
; PrintRaw - writes (RCX=ptr, RDX=len) bytes to stdout, no newline
; ----------------------------------------------------------------------------
PrintRaw PROC
    push rbp
    mov rbp, rsp
    push rbx                ; [rbp-8]
    push rsi                ; [rbp-16]
    push rdi                ; [rbp-24]
    sub rsp, 56             ; locals at [rbp-32..rbp-80); shadow at [rsp..rsp+32)
    mov rbx, rcx                ; ptr
    mov rdi, rdx                ; len
    mov rcx, -11
    call [g_ApiTable.pGetStdHandle]
    mov rcx, rax
    mov rdx, rbx
    mov r8, rdi
    lea r9, [rbp-32]
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pWriteFile]
    add rsp, 56
    pop rdi
    pop rsi
    pop rbx
    leave
    ret
PrintRaw ENDP

; ----------------------------------------------------------------------------
; PrintHex64 - prints RCX as 16 hex chars (no newline)
; ----------------------------------------------------------------------------
PrintHex64 PROC
    push rbp
    mov rbp, rsp
    push rbx                ; [rbp-8]
    push rsi                ; [rbp-16]
    push rdi                ; [rbp-24]
    sub rsp, 56             ; locals at [rbp-32..rbp-80); shadow at [rsp..rsp+32)
    mov rbx, rcx
    lea rdi, hexBuf
    mov rcx, 16
    lea rsi, hexDigits
@@phx64_loop:
    mov rax, rbx
    rol rax, 4
    mov rbx, rax
    and rax, 0Fh
    mov al, [rsi + rax]
    mov [rdi], al
    inc rdi
    dec rcx
    jnz @@phx64_loop
    mov byte ptr [rdi], 0
    mov rcx, -11
    call [g_ApiTable.pGetStdHandle]
    mov rcx, rax
    lea rdx, hexBuf
    mov r8d, 16
    lea r9, [rbp-32]
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pWriteFile]
    add rsp, 56
    pop rdi
    pop rsi
    pop rbx
    leave
    ret
PrintHex64 ENDP

.DATA
ALIGN 16
static_gov   GOV_STATE <0>
static_model MODEL_STATE <0>

END
