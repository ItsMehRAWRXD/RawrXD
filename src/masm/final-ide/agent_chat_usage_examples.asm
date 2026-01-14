;==========================================================================
; agent_chat_usage_examples.asm - Concrete Examples of Advanced Agent Chat
; ==========================================================================
; This file demonstrates real-world usage patterns for the enhanced agent
; chat system, showing how different modes handle the same queries.
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; EXAMPLE 1: Simple Ask Mode (Basic Q&A)
; ==========================================================================

; User Query:
;   "What's the best way to organize the quantization kernels?"

; MASM Processing:
example_ask_mode PROC
    push rbx
    sub rsp, 48
    
    ; Initialize for Ask mode
    mov ecx, AGENT_MODE_ASK
    call agent_set_mode_advanced
    
    ; Send message
    lea rcx, szExample1Query
    lea rdx, context_ask_mode
    call agent_send_message_with_reasoning
    
    ; Response automatically formatted as:
    ; [REASONING]
    ; WHAT: Organize quantization kernels
    ; WHY: Avoid code duplication, improve maintainability
    ; HOW: Create modular functions for RawrQ, RawrZ, RawrX formats
    ; FIX: Use kernel registry pattern + function pointers
    ; Confidence: PROBABLE (82%)
    
    add rsp, 48
    pop rbx
    ret
example_ask_mode ENDP

.data
    szExample1Query BYTE "What's the best way to organize the quantization kernels?",0

;==========================================================================
; EXAMPLE 2: Debug Mode (Execution Trace)
; ==========================================================================

; User Query:
;   "Debug: Why does model loading fail with CUDA error at line 342?"

; MASM Processing:
example_debug_mode PROC
    push rbx
    sub rsp, 48
    
    ; Initialize for Debug mode
    mov ecx, AGENT_MODE_DEBUG
    call agent_set_mode_advanced        ; Auto-selects RESPONSE_TRACE
    
    ; Send message with execution context
    lea rcx, szExample2Query
    lea rdx, context_debug_with_stack
    call agent_send_message_with_reasoning
    
    ; Response formatted as full trace:
    ; [TRACE]
    ; Step 1: Load GGUF header
    ;   → Memory read at 0x7FFF0000
    ;   → Magic: 0x47475546 (GGUF) ✓
    ; Step 2: Parse tensor metadata
    ;   → 24 tensors detected
    ;   → Total size: 512 MB
    ; Step 3: Allocate CUDA memory
    ;   → QueryDeviceMemory: 4096 MB available
    ;   → CudaMalloc(512 MB): CUDA_ERROR_OUT_OF_MEMORY ✗
    ;   [DECISION POINT]
    ;   → Cause: Fragmentation in GPU memory
    ;   → Options:
    ;      1. CudaDeviceReset() then retry (risk 15%)
    ;      2. Reduce precision to int8 (risk 5%)
    ;      3. Stream from CPU (risk 30%)
    ;   → Recommended: Option 2
    ; Confidence: CERTAIN (96%)
    
    add rsp, 48
    pop rbx
    ret
example_debug_mode ENDP

.data
    szExample2Query BYTE "Debug: Why does model loading fail with CUDA error at line 342?",0

;==========================================================================
; EXAMPLE 3: Optimize Mode (Performance)
; ==========================================================================

; User Query:
;   "Optimize the matrix multiplication in kernel.asm for AVX-512"

; MASM Processing:
example_optimize_mode PROC
    push rbx
    push rsi
    sub rsp, 96
    
    ; Initialize for Optimize mode
    mov ecx, AGENT_MODE_OPTIMIZE
    call agent_set_mode_advanced
    
    ; Send message with hotpatch context
    lea rcx, szExample3Query
    lea rdx, context_optimize_with_perf
    call agent_send_message_with_reasoning
    
    ; Response includes performance recommendations:
    ; [TRACE]
    ; Performance Analysis:
    ;   Current: Inner loop at line 156-201
    ;   Hot: 89% of execution time
    ;   Throughput: 45% of peak bandwidth
    ;   Cache misses: 32% (high)
    ;
    ; Optimization Candidates:
    ;   1. AVX-512 FMA operations (4x speedup)
    ;      Risk: 15% | Hotpatch: Byte-level
    ;      Details: Replace scalar FMA with EVEX instructions
    ;      Patch size: 128 bytes
    ;   2. Data layout: SoA instead of AoS (1.8x speedup)
    ;      Risk: 5% | Hotpatch: Memory layout
    ;      Details: Improve cache locality
    ;      Requires: Data structure change
    ;   3. Parallelize outer loop (2.2x on 4 cores)
    ;      Risk: 20% | Hotpatch: Server-layer
    ;      Details: Split work across threads
    ;      Sync overhead: ~5%
    ;
    ; Recommended: Apply 1+2 (6x combined)
    ; [HOTPATCH GENERATED]
    ; Applying byte-level patch to kernelasm_local:156-201
    ; Live update: No rebuild required
    ; Verification: Compare outputs before/after
    ;
    ; Confidence: PROBABLE (85%)
    
    add rsp, 48
    pop rsi
    pop rbx
    ret
example_optimize_mode ENDP

.data
    szExample3Query BYTE "Optimize the matrix multiplication in kernel.asm for AVX-512",0

;==========================================================================
; EXAMPLE 4: Plan Mode (Architecture)
; ==========================================================================

; User Query:
;   "Plan the migration from GGUF to a custom quantization format"

; MASM Processing:
example_plan_mode PROC
    push rbx
    push rsi
    sub rsp, 96
    
    ; Initialize for Plan mode
    mov ecx, AGENT_MODE_PLAN
    call agent_set_mode_advanced
    
    ; Create multi-step plan
    lea rcx, szExample4Objective
    lea rdx, szExample4Constraints
    call agent_create_multi_step_plan
    
    ; Returns plan with steps:
    ;
    ; PLAN: GGUF → Custom Format Migration
    ; Total Steps: 7
    ; Estimated Time: 3.5 hours
    ; Overall Confidence: 74%
    ;
    ; ┌─ STEP 1: Audit GGUF loading code
    ; │  Risk: Low (10%)
    ; │  Confidence: 95%
    ; │  Time: 15 min
    ; │  Purpose: Document current implementation
    ; │  Precondition: None
    ; │  Impact: Documentation only (no changes)
    ; │
    ; ├─ STEP 2: Design new format specification
    ; │  Risk: Medium (30%)
    ; │  Confidence: 80%
    ; │  Time: 30 min
    ; │  Purpose: Define metadata, tensor layout, magic bytes
    ; │  Precondition: Complete Step 1
    ; │  Impact: Design document only
    ; │
    ; ├─ STEP 3: Implement format reader
    ; │  Risk: Medium (25%)
    ; │  Confidence: 75%
    ; │  Time: 45 min
    ; │  Purpose: Write load_new_format() function
    ; │  Precondition: Complete Step 2
    ; │  Impact: ~200 lines of code
    ; │
    ; ├─ STEP 4: Verify backward compatibility
    ; │  Risk: High (40%) ← Decision point: Confidence < 78%
    ; │  Confidence: 65%
    ; │  Time: 60 min
    ; │  Purpose: GGUF ↔ new format conversion
    ; │  Precondition: Complete Steps 2-3
    ; │  Impact: Conversion overhead ~5%
    ; │  [DECISION]
    ; │  Confidence 65% < threshold 78%
    ; │  → Ask user: "Proceed with compatibility layer? [Y/N]"
    ; │  → If N: Skip to Step 6 (lose GGUF compatibility)
    ; │
    ; ├─ STEP 5: Optimize hot paths
    ; │  Risk: Medium (20%)
    ; │  Confidence: 70%
    ; │  Time: 45 min
    ; │  Purpose: SIMD optimizations
    ; │  Precondition: Complete Step 3
    ; │  Impact: 1.5-2x speedup
    ; │
    ; ├─ STEP 6: Benchmark
    ; │  Risk: Low (5%)
    ; │  Confidence: 85%
    ; │  Time: 30 min
    ; │  Purpose: Validate performance
    ; │  Impact: Performance numbers only
    ; │
    ; └─ STEP 7: Update docs
    ;    Risk: Low (2%)
    ;    Confidence: 90%
    ;    Time: 20 min
    ;    Impact: Documentation update
    ;
    ; Ready to execute? [Yes] [Review] [Modify]
    
    add rsp, 96
    pop rsi
    pop rbx
    ret
example_plan_mode ENDP

.data
    szExample4Objective     BYTE "Migrate from GGUF to custom quantization format",0
    szExample4Constraints   BYTE "Must maintain backward compatibility | Target: 2-3 hours | Single developer",0

;==========================================================================
; EXAMPLE 5: Teaching Mode (Educational)
; ==========================================================================

; User Query:
;   "Teach me about AVX-512 vector instructions for quantization"

; MASM Processing:
example_teach_mode PROC
    push rbx
    sub rsp, 48
    
    ; Initialize for Teach mode
    mov ecx, AGENT_MODE_TEACH
    call agent_set_mode_advanced
    
    ; Send educational query
    lea rcx, szExample5Query
    lea rdx, context_teach_mode
    call agent_send_message_with_reasoning
    
    ; Response formatted for learning:
    ; [REASONING + CONCEPTS]
    ;
    ; CONCEPT 1: Vector Registers & ZMM
    ;   → 512-bit register (512/32 = 16 float32s at once)
    ;   → 2x wider than AVX2 (256-bit/8 floats)
    ;   → Example: vbroadcastss zmm0, [rax]
    ;      Load 1 float into all 16 slots of ZMM0
    ;   Key Point: Think "parallelism over single operations"
    ;
    ; CONCEPT 2: Float Quantization Problem
    ;   → Need to convert 32-bit float → 4-bit or 8-bit integer
    ;   → Challenge: Loss of range (32 billion values → 16 values)
    ;   → Solution: Find min/max in block, scale/offset, round
    ;   Key Point: "Lossy compression: what can you afford to lose?"
    ;
    ; CONCEPT 3: SIMD Quantization Loop
    ;   → Process 16 floats in parallel with AVX-512
    ;   → Step 1: Load 16 floats (vmovups)
    ;   → Step 2: Compute min/max across all 16 (vreducemin/max)
    ;   → Step 3: Scale to target range (vmulps, vsubps)
    ;   → Step 4: Convert to integers (vcvttps2dq, vpmovdb)
    ;   Key Point: "Each instruction processes entire vector"
    ;
    ; CONCEPT 4: Confidence & Risk
    ;   → Why AVX-512 is powerful: 4x wider = 4x faster
    ;   → Why it's risky: Precision loss may break models
    ;   → Solution: Always verify numerical accuracy
    ;   Key Point: "Performance + correctness = validation"
    ;
    ; HANDS-ON: Try this example
    ;   ```asm
    ;   vbroadcastss zmm0, [min_value]    ; Load min into all 16 slots
    ;   vsubps zmm1, zmm2, zmm0           ; Subtract min (normalize)
    ;   vmulps zmm3, zmm1, scale_factor   ; Scale to 0-15 range
    ;   vcvttps2dq zmm4, zmm3             ; Convert to int (truncate)
    ;   vpmovdb xmm5, zmm4                ; Pack 16 ints → 16 bytes
    ;   ```
    ;
    ; Confidence: CERTAIN (92%)
    
    add rsp, 48
    pop rbx
    ret
example_teach_mode ENDP

.data
    szExample5Query BYTE "Teach me about AVX-512 vector instructions for quantization",0

;==========================================================================
; EXAMPLE 6: Real-Time Hallucination Correction
; ==========================================================================

; Scenario: Model generates incorrect function name

; MASM Processing:
example_hallucination_correction PROC
    push rbx
    sub rsp, 96
    
    ; Simulate streaming response with error
    
    ; Token 1: "You" → CLEAN
    lea rcx, "You"
    mov edx, 240        ; High confidence
    call agent_stream_token
    
    ; Token 2: "can" → CLEAN
    lea rcx, "can"
    mov edx, 230
    call agent_stream_token
    
    ; Token 3: "use" → CLEAN
    lea rcx, "use"
    mov edx, 235
    call agent_stream_token
    
    ; Token 4: "the" → CLEAN
    lea rcx, "the"
    mov edx, 245
    call agent_stream_token
    
    ; Token 5: "vbroadcast_simd_avx512_ultra"
    ; ↓ Check symbol table
    ; ✗ NOT FOUND (fabricated name)
    ; ↓ Check similar functions
    ; ✓ Found: "vbroadcastss" (Levenshtein distance 4)
    ; ↓ Confidence: 140 (moderate)
    ; ↓ Request correction from hotpatcher
    
    lea rcx, "vbroadcast_simd_avx512_ultra"
    mov edx, 140        ; Moderate confidence
    call agent_stream_token
    
    ; Returns: 0 (blocked) with correction flag set
    ; Auto-correction: Replace with "vbroadcastss"
    
    ; Continue with corrected token
    lea rcx, "vbroadcastss"
    mov edx, 220        ; Corrected version
    call agent_stream_token
    
    ; Final response after complete stream:
    lea rcx, full_response_buffer
    call agent_stream_complete
    
    ; Output includes:
    ; "You can use the vbroadcastss instruction..."
    ; [AUTO-CORRECTION] 
    ; Replaced "vbroadcast_simd_avx512_ultra" 
    ; with "vbroadcastss" (confidence: 87%)
    
    add rsp, 96
    pop rbx
    ret
example_hallucination_correction ENDP

;==========================================================================
; EXAMPLE 7: Self-Correction from Failure
; ==========================================================================

; Scenario: Multi-step plan fails at step 3, automatic recovery

; MASM Processing:
example_self_correction PROC
    push rbx
    push rsi
    sub rsp, 96
    
    ; Execute plan until step 3 fails
    call agent_execute_plan_with_decision_making
    
    ; Step 3 failed: "Invalid AVX-512 instruction encoding"
    ; Workflow state: WORKFLOW_EXECUTING → detect failure
    
    ; Trigger self-correction
    call agent_self_correct_from_failure
    ; Returns: decision_id
    
    ; Agent analyzes:
    ; Error Type: "Invalid instruction" 
    ; Historical Patterns:
    ;   - Learned Pattern #42: Same error, success via intrinsics
    ;     Success Rate: 95%
    ; Action: Apply learned pattern
    ;
    ; Backtrack point: Step 2 (data layout redesign)
    ; New approach: Use _mm512_* intrinsics instead of raw EVEX
    ; Re-execute Step 3 with new approach
    ;
    ; Result: SUCCESS
    ; Step 3 now passes with corrected AVX-512 call
    ; Learning: Update pattern #42 success counter
    ; Confidence: CERTAIN (97%)
    
    add rsp, 96
    pop rsi
    pop rbx
    ret
example_self_correction ENDP

;==========================================================================
; EXAMPLE 8: Cross-File Impact Analysis
; ==========================================================================

; Scenario: Renaming a function, analyze impact

; MASM Processing:
example_cross_file_impact PROC
    push rbx
    sub rsp, 96
    
    ; Analyze impact of changing quantize_float32() → quantize_fp32_simd()
    lea rcx, "src/quantization.asm"        ; File
    mov edx, 45                             ; Start line
    mov r8d, 67                             ; End line
    mov r9d, 0                              ; Change type: rename
    call agent_analyze_cross_file_impact
    
    ; Agent reports:
    ; [IMPACT ANALYSIS]
    ; File: src/quantization.asm
    ; Changed: quantize_float32() → quantize_fp32_simd()
    ; Lines affected: 45-67
    ;
    ; Direct Dependencies (12 total):
    ;   ✓ kernelasm_local:156 - quantize_float32() call
    ;   ✓ kernelasm_local:201 - quantize_float32() call
    ;   ✓ model_loadercpp_local:342 - extern reference
    ;   ✗ test_quantasm_local:78 - hardcoded call (WILL BREAK)
    ;   ... (8 more)
    ;
    ; Indirect Dependencies:
    ;   ✓ inference_engine.asm → kernel.asm → quantize_float32()
    ;
    ; Risk Assessment:
    ;   Breaking Change Risk: 45% (moderate)
    ;   Performance Impact: -2% (negligible)
    ;   Files at Risk: test_quant.asm, test_model.cpp
    ;
    ; Recommendation:
    ;   Apply byte-level hotpatch to update all callers automatically
    ;   Patch cost: ~50 ms
    ;   No rebuild required
    ;   Confidence: CERTAIN (94%)
    
    add rsp, 96
    pop rbx
    ret
example_cross_file_impact ENDP

;==========================================================================
; HELPER PROCEDURES (Stubs)
;==========================================================================
PUBLIC example_ask_mode
PUBLIC example_debug_mode
PUBLIC example_optimize_mode
PUBLIC example_plan_mode
PUBLIC example_teach_mode
PUBLIC example_hallucination_correction
PUBLIC example_self_correction
PUBLIC example_cross_file_impact

;==========================================================================
; GLOBAL CONTEXT OBJECTS
;==========================================================================

.data?
    context_ask_mode                BYTE 512 DUP (?)
    context_debug_with_stack        BYTE 512 DUP (?)
    context_optimize_with_perf      BYTE 512 DUP (?)
    context_teach_mode              BYTE 512 DUP (?)
    full_response_buffer            BYTE 8192 DUP (?)

END





