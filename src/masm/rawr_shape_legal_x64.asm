; rawr_shape_legal_x64.asm — legality only; ROWS ≠ LOCAL
OPTION CASEMAP:NONE
INCLUDE rawr_capabilities.inc
.code
PUBLIC RawrShapeLegal

; RCX=RawrKernelShape* RDX=RawrGpuCaps*
; EAX=1 legal, 0 reject
RawrShapeLegal PROC
    push rbx
    mov  r8, rcx
    mov  r9, rdx

    mov  eax, [r8].RawrKernelShape.LocalX
    mov  ebx, [r8].RawrKernelShape.LocalY
    mov  ecx, [r8].RawrKernelShape.LocalZ
    test eax, eax
    jz   bad
    test ebx, ebx
    jz   bad
    test ecx, ecx
    jz   bad

    ; invocations = LocalX*LocalY*LocalZ with overflow reject
    mul  ebx
    jo   bad
    mul  ecx
    jo   bad
    cmp  eax, [r9].RawrGpuCaps.MaxWGInvocations
    ja   bad

    mov  eax, [r8].RawrKernelShape.LocalX
    cmp  eax, [r9].RawrGpuCaps.MaxWGX
    ja   bad
    mov  eax, [r8].RawrKernelShape.LocalY
    cmp  eax, [r9].RawrGpuCaps.MaxWGY
    ja   bad
    mov  eax, [r8].RawrKernelShape.LocalZ
    cmp  eax, [r9].RawrGpuCaps.MaxWGZ
    ja   bad

    mov  eax, [r8].RawrKernelShape.SharedBytes
    cmp  eax, [r9].RawrGpuCaps.MaxSharedBytes
    ja   bad

    ; RowsPerWG is kernel mapping — not compared to MaxWGInvocations.
    mov  eax, [r8].RawrKernelShape.RowsPerWG
    test eax, eax
    jz   bad

    mov  eax, 1
    pop  rbx
    ret
bad:
    xor  eax, eax
    pop  rbx
    ret
RawrShapeLegal ENDP
END
