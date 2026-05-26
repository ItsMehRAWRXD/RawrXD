include Sovereign_Common.inc
extern Kernel_Attention_Optimized_128 : proc

.CODE
PUBLIC Inference_Dispatch_Layer
Inference_Dispatch_Layer PROC
    ; RCX = Layer Index
    ; RDX = Pointer to Tensor Buffer
    
    push rbp
    mov rbp, rsp
    
    ; Setup Kernel Parameters
    ; Utilizing the already pinned ZMM registers
    call Kernel_Attention_Optimized_128
    
    pop rbp
    ret
Inference_Dispatch_Layer ENDP
END
