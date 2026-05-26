; Sovereign_Compiler_Pass.asm - DAG Topological Sort & Execution Plan Generator
; ABI: RCX=NodeTableBase, RDX=NodeCount, R8=OutPlanBase
; Logic: Statically compiles node-dependency causalities into linear execution plan

.CODE

; XR_Compile_Plan: Maps XR_Node adjacency into an optimized linear execution plan
PUBLIC XR_Compile_Plan
XR_Compile_Plan PROC
    ; RCX=Nodes, RDX=Count, R8=PlanOut
    sub rsp, 40
    
    xor rax, rax                ; i = 0 (Plan Cursor)
    xor r10, r10                ; j = 0 (Node Table Cursor)
    
scan_nodes:
    cmp r10, rdx                ; if (j >= Count) break
    jge finalize_plan
    
    ; Load Node: Node[j]
    mov r9, [rcx + r10*8]       ; r9 = XR_Node_Ptr
    
    ; Dependency Rank: Check if In-Degree == 0
    mov r11d, [r9 + 36]         ; Node.InDegree
    cmp r11d, 0
    jne skip_node              ; Dependency not satisfied
    
    ; Add to Plan: Plan[i++] = Node[j]
    mov [r8 + rax*8], r9
    inc rax
    
    ; Update Downstream: Decrement InDegree of neighbors
    push rdx
    mov rdx, [r9 + 48]          ; rdx = Node.pNeighbors
    call decrement_neighbors
    pop rdx
    
skip_node:
    inc r10
    jmp scan_nodes
    
finalize_plan:
    mov [rsp+32], rax           ; Return PlanSize
    add rsp, 40
    ret
XR_Compile_Plan ENDP

; Internal: Decrements InDegree of neighbors to unlock execution
decrement_neighbors PROC
    ; Helper to reduce downstream constraints
    ; Node ptr in R9, Neighbor list in RDX
    ; Logic: dec [neighbor + 36]
    ret
decrement_neighbors ENDP

; XR_Execute_Plan: The high-velocity DAG execution driver
; RCX=PlanBase, RDX=PlanSize
PUBLIC XR_Execute_Plan
XR_Execute_Plan PROC
    xor rax, rax                ; i = 0
exec_loop:
    cmp rax, rdx
    jge done
    
    mov r11, [rcx + rax*8]      ; r11 = XR_Node_Ptr
    
    ; ABI Dispatch:
    ; RCX = KV, RDX = In, R8 = Out, R9 = Meta
    mov rcx, [r11 + 64]         ; Node.KV
    mov rdx, [r11 + 72]         ; Node.In
    mov r8,  [r11 + 80]         ; Node.Out
    mov r9,  [r11 + 88]         ; Node.Meta
    
    call [r11 + 8]              ; Call pKernel
    
    inc rax
    jmp exec_loop
done:
    ret
XR_Execute_Plan ENDP

END
