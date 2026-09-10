; RuntimeEvidence512_InitC.asm — C-callable Init with seqCap in r9d path.
; Win64: EvidenceInit512_C(rcx=st, rdx=buf, r8=cap, r9=runId, stack+28h unused)
; Actual 5th arg seqCap fixed to 512 for collection harnesses.
OPTION CASEMAP:NONE
EXTERN EvidenceInit512:PROC
PUBLIC EvidenceInit512_C

.code
EvidenceInit512_C PROC
    ; Shadow space + align: push seqCap=512 as 5th argument.
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], 512
    call EvidenceInit512
    add  rsp, 28h
    ret
EvidenceInit512_C ENDP
END
