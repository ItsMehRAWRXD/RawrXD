; =============================================================================
; Sovereign_JIT_Engine.asm - The Sovereign OS Runtime instruction Synthesizer
; Purpose: Template-based opcode injection for zero-dependency JIT.
; Architecture: x64 MASM, Zero-Dependency.
; =============================================================================

.CODE

; --- Opcode Templates (Byte Arrays) ---

; Standard Kernel Prologue: 
; push rbp; mov rbp, rsp; sub rsp, 32; ...
; 48 89 E5 48 83 EC 20
ALIGN 16
JIT_PROLOGUE    DB 048h, 089h, 0E5h, 048h, 083h, 0ECh, 020h
JIT_PROLOGUE_SZ EQU $ - JIT_PROLOGUE

; Standard Kernel Epilogue:
; add rsp, 32; pop rbp; ret
; 48 83 C4 20 5D C3
ALIGN 16
JIT_EPILOGUE    DB 048h, 083h, 0C4h, 020h, 05Dh, 0C3h
JIT_EPILOGUE_SZ EQU $ - JIT_EPILOGUE

; AVX-512 FMA Opcode Template (Fragment)
; vfmadd213ps zmm0, zmm1, zmm2
; 62 F1 75 48 A8 C2
ALIGN 16
JIT_FMA_ZMM     DB 062h, 0F1h, 075h, 048h, 0A8h, 0C2h
JIT_FMA_ZMM_SZ  EQU $ - JIT_FMA_ZMM

; -----------------------------------------------------------------------------------------
; Phi-3 Q2_K Dequant & FMA AVX-512 (Ring-3 JIT Stub)
; -----------------------------------------------------------------------------------------
; This represents a fused block targeting phi3-mini-Q2_K. 
; To prevent memory spills, we dequantize Q2_K into ZMM2 and immediately FMA.
; 
; vpmovzxbd zmm2, ymm0               (Zero-extend Q2_K byte index)
; vpslld    zmm2, zmm2, 2            (Scale index)
; vgatherdps zmm3, [rcx + zmm2]      (Gather F32 scales)
; vfmadd213ps zmm0, zmm3, zmm1       (Fused Multiply-Add direct to Accumulator)
ALIGN 16
JIT_Q2K_FMA     DB 062h, 0F2h, 07Dh, 048h, 031h, 0D0h  ; vpmovzxbd zmm2, ymm0
                DB 062h, 0F1h, 06Dh, 048h, 072h, 0F2h, 002h ; vpslld zmm2, zmm2, 2
                DB 062h, 0F2h, 07Dh, 048h, 092h, 01Ch, 011h ; vgatherdps zmm3, [rcx+zmm2]
                DB 062h, 0F1h, 065h, 048h, 0A8h, 0C1h  ; vfmadd213ps zmm0, zmm3, zmm1
JIT_Q2K_FMA_SZ  EQU $ - JIT_Q2K_FMA

; -----------------------------------------------------------------------------------------
; XR_JIT_Emit_Kernel
; Inputs:  RCX = Destination Executable Buffer
;          RDX = OpType (Logical operation to synthesize)
; Outputs: RAX = Size of generated machine code
; -----------------------------------------------------------------------------------------
PUBLIC XR_JIT_Emit_Kernel
XR_JIT_Emit_Kernel PROC
    push    rdi
    push    rsi
    mov     rdi, rcx                    ; RDI = Target Executable Memory
    
    ; [1] Emit Prologue (Stack Pivot/Protection omitted for raw threading loops)
    lea     rsi, JIT_PROLOGUE
    mov     rcx, JIT_PROLOGUE_SZ
    rep     movsb
    
    ; [2] Select Opcode Sequence
    cmp     rdx, 1                      ; 1 = MATMUL_FMA (FP32)
    je      @@emit_fma
    cmp     rdx, 2                      ; 2 = MATMUL_Q2_K (Phi-3)
    je      @@emit_q2k
    jmp     @@emit_default
    
@@emit_fma:
    lea     rsi, JIT_FMA_ZMM
    mov     rcx, JIT_FMA_ZMM_SZ
    rep     movsb
    jmp     @@emit_epilogue

@@emit_q2k:
    lea     rsi, JIT_Q2K_FMA
    mov     rcx, JIT_Q2K_FMA_SZ
    rep     movsb
    jmp     @@emit_epilogue

@@emit_default:
    ; NOP sled for unhandled OpType
    mov     al, 090h
    stosb

@@emit_epilogue:
    ; [3] Emit Epilogue
    lea     rsi, JIT_EPILOGUE
    mov     rcx, JIT_EPILOGUE_SZ
    rep     movsb

    pop     rsi
    pop     rdi
    ret
XR_JIT_Emit_Kernel ENDP

; --- Hardware-Specific Acceleration (Standard x64 + AVX-512) ---

; VNNI: VPDPBUSD - Dot product of signed/unsigned bytes with saturation
; For low-precision inference acceleration
; 62 F2 7D 48 50 C1
ALIGN 16
JIT_VNNI_DOT    DB 062h, 0F2h, 07Dh, 048h, 050h, 0C1h
JIT_VNNI_DOT_SZ EQU $ - JIT_VNNI_DOT

; Standard x64 atomic exchange (for lockless queue updates)
; xchg [rcx], rax
; 48 87 01
ALIGN 16
JIT_XCHG_RAX    DB 048h, 087h, 001h
JIT_XCHG_RAX_SZ EQU $ - JIT_XCHG_RAX

; Probe: Atomic Increment of Telemetry Counter
; lock inc qword ptr [r15] 
; (We reserve R15 as the Telemetry Context Pointer in JIT-space)
; 48 F0 41 FF 07
ALIGN 16
JIT_PROBE_INC   DB 048h, 0F0h, 041h, 0FFh, 007h
JIT_PROBE_INC_SZ EQU $ - JIT_PROBE_INC

; Probe: Time-Stamp Capture
; rdtsc; shl rdx, 32; or rax, rdx; mov [r15 + 8], rax
; 0F 31 48 C1 E2 20 48 09 D0 49 89 47 08
ALIGN 16
JIT_PROBE_TSC   DB 00Fh, 031h, 048h, 0C1h, 0E2h, 020h, 048h, 009h, 0D0h, 049h, 089h, 047h, 008h
JIT_PROBE_TSC_SZ EQU $ - JIT_PROBE_TSC

; -----------------------------------------------------------------------------------------
; XR_JIT_Inject_Probe
; Inputs:  RCX = Destination Buffer
;          RDX = Probe Type (0=INC, 1=TSC)
; Outputs: RAX = Bytes Written
; -----------------------------------------------------------------------------------------
PUBLIC XR_JIT_Inject_Probe
XR_JIT_Inject_Probe PROC
    push    rsi
    push    rdi
    mov     rdi, rcx
    
    cmp     rdx, 0
    je      @@emit_inc
    cmp     rdx, 1
    je      @@emit_tsc
    xor     rax, rax
    jmp     @@exit

@@emit_inc:
    lea     rsi, JIT_PROBE_INC
    mov     rcx, JIT_PROBE_INC_SZ
    rep     movsb
    mov     rax, JIT_PROBE_INC_SZ
    jmp     @@exit

@@emit_tsc:
    lea     rsi, JIT_PROBE_TSC
    mov     rcx, JIT_PROBE_TSC_SZ
    rep     movsb
    mov     rax, JIT_PROBE_TSC_SZ

@@exit:
    pop     rdi
    pop     rsi
    ret
XR_JIT_Inject_Probe ENDP

; -----------------------------------------------------------------------------------------
; XR_JIT_Emit_LoadImm64
; Purpose: Dynamically emits 'mov R64, IMM64' to pass physical addresses into JIT blocks
; Inputs:  RCX = Target Executable Buffer
;          RDX = Target Register (0=RAX, 1=RCX, 2=RDX, 3=RBX, 6=RSI, 7=RDI, 8-15=R8-R15)
;          R8  = Immediate 64-bit value to embed (e.g., VRAM Offset pointer)
; Outputs: RAX = Size of generated machine code (10 bytes)
; -----------------------------------------------------------------------------------------
PUBLIC XR_JIT_Emit_LoadImm64
XR_JIT_Emit_LoadImm64 PROC
    push    rdi
    mov     rdi, rcx
    
    ; Determine REX prefix (48h or 49h)
    mov     al, 048h                ; Base REX.W (64-bit operand)
    cmp     rdx, 8
    jl      @@base_reg
    
    mov     al, 049h                ; REX.W | REX.B (Extended Register R8-R15)
    and     dl, 7                   ; Mask high bit for opcode byte
    
@@base_reg:
    stosb                           ; Write REX Prefix

    ; Determine Opcode (B8 + Register Index)
    mov     al, 0B8h                ; MOV R64, imm64 base opcode
    add     al, dl                  ; + Reg Index
    stosb                           ; Write Opcode

    ; Write Immediate Payload (8 Bytes)
    mov     rax, r8
    stosq                           ; Write Payload Address literal
    
    mov     rax, 10                 ; Instruction is exactly 10 bytes long
    pop     rdi
    ret
XR_JIT_Emit_LoadImm64 ENDP

; -----------------------------------------------------------------------------------------
; XR_JIT_Emit_LoopEnd
; Purpose: Emits loop termination boundary: 'dec RDX; jnz <loop_start>'
; Inputs:  RCX = Target Executable Buffer
;          RDX = Backjmp Target Address (absolute loop start address in JIT mem)
; Outputs: RAX = Size of generated machine code (9 bytes)
; -----------------------------------------------------------------------------------------
PUBLIC XR_JIT_Emit_LoopEnd
XR_JIT_Emit_LoopEnd PROC
    push    rdi
    mov     rdi, rcx
    
    ; Emit 'dec rdx' -> 48 FF CA
    mov     al, 048h
    stosb
    mov     al, 0FFh
    stosb
    mov     al, 0CAh
    stosb

    ; Emit 'jnz' near -> 0F 85
    mov     al, 00Fh
    stosb
    mov     al, 085h
    stosb

    ; Calculate 32-bit relative offset: target - (current_ip + 4)
    ; current_ip = RDI (before writing 4 bytes)
    mov     r8, rdx                 ; R8 = target
    mov     r9, rdi
    add     r9, 4                   ; R9 = current_ip + 4 (instruction end)
    sub     r8, r9                  ; R8 = rel32 offset
    
    mov     eax, r8d                ; Truncate/Write as 32-bit signed
    stosd

    mov     rax, 9                  ; Total bytes emitted (3 + 2 + 4 = 9)
    pop     rdi
    ret
XR_JIT_Emit_LoopEnd ENDP

; -----------------------------------------------------------------------------------------
; XR_JIT_Emit_AddImm32
; Purpose: Emits 'add R64, imm32' to advance pointer strides inside the cyclic graph
; Inputs:  RCX = Target Executable Buffer
;          RDX = Target Register (0=RAX, 1=RCX, 2=RDX, 3=RBX, 6=RSI, 7=RDI, 8-15=R8-R15)
;          R8  = Immediate 32-bit stride length
; Outputs: RAX = Size of generated machine code (7 bytes)
; -----------------------------------------------------------------------------------------
PUBLIC XR_JIT_Emit_AddImm32
XR_JIT_Emit_AddImm32 PROC
    push    rdi
    mov     rdi, rcx
    
    ; Determine REX prefix (48h or 49h)
    mov     al, 048h                ; Base REX.W (64-bit operand)
    cmp     rdx, 8
    jl      @@base_reg
    
    mov     al, 049h                ; REX.W | REX.B (Extended Register R8-R15)
    and     dl, 7                   ; Mask high bit for opcode byte
    
@@base_reg:
    stosb                           ; Write REX Prefix

    ; Emit Opcode (81 = ADD r/m64, imm32)
    mov     al, 081h
    stosb

    ; ModR/M byte for ADD is 11 000 reg (C0 + reg)
    mov     al, 0C0h
    add     al, dl
    stosb

    ; Write Immediate Payload (4 Bytes)
    mov     eax, r8d
    stosd
    
    mov     rax, 7                  ; Instruction is 7 bytes long
    pop     rdi
    ret
XR_JIT_Emit_AddImm32 ENDP

END

