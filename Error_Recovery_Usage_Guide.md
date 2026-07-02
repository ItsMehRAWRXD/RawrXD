# RawrXD Error Recovery System - Usage Guide

## Overview

The RawrXD Error Recovery System provides robust self-healing capabilities for the Sovereign Engine, specifically designed to handle:
- **Transient failures** with exponential backoff retry
- **"No response" scenarios** with autopilot recovery
- **Circuit breaker pattern** to prevent cascade failures
- **Graceful degradation** to fallback models

## Quick Start

### 1. Initialize the Recovery System

```asm
; Initialize with circuit breaker and fallback enabled
mov     ecx, 5          ; max_retries = 5
mov     edx, 1          ; enable_fallback = true
mov     r8d, 1          ; enable_circuit_breaker = true
call    Recovery_Init
```

### 2. Configure Autopilot for "No Response" Handling

```asm
; Configure autopilot recovery
mov     ecx, 3          ; max_autopilot_attempts = 3
mov     edx, 5000       ; autopilot_timeout_ms = 5000 (5 seconds)
call    Recovery_ConfigureAutopilot
```

### 3. Execute Operations with Automatic Retry

```asm
; Define your operation function
MyInferenceOperation PROC
    ; Your inference code here
    ; Return 1 for success, 0 for failure
    ret
MyInferenceOperation ENDP

; Execute with automatic retry
lea     rcx, MyInferenceOperation
xor     edx, edx        ; context = NULL
call    Recovery_ExecuteWithRetry
; RAX = 1 if succeeded (possibly after retries), 0 if failed
```

## Handling "No Response" Scenarios

### The Problem

When the model or service doesn't respond (common in autopilot scenarios), you need graceful recovery without crashing the system.

### The Solution

Use the autopilot recovery system:

```asm
; When you detect no response
mov     rcx, request_id     ; Unique request identifier
call    Recovery_HandleNoResponse

; Check if autopilot is now active
call    Recovery_IsAutopilotRecovery
cmp     rax, 1
je      .in_recovery_mode

; Continue with normal processing...

.in_recovery_mode:
; Autopilot is handling recovery - you can:
; 1. Wait and retry with shorter timeout
; 2. Switch to fallback model
; 3. Queue request for later processing

; When recovery is complete, acknowledge:
call    Recovery_AcknowledgeAutopilot
```

### C/C++ Interface

```c
#include "RawrXD_Error_Recovery.h"

// Initialize
Recovery_Init(5, true, true);

// Configure autopilot
Recovery_ConfigureAutopilot(3, 5000);

// Handle no response
int result = Recovery_HandleNoResponse(request_id);
if (result) {
    // Recovery initiated
    if (Recovery_IsAutopilotRecovery()) {
        // In recovery mode - handle gracefully
        // ...
        
        // Acknowledge when done
        Recovery_AcknowledgeAutopilot();
    }
}
```

## Circuit Breaker Pattern

The circuit breaker prevents cascade failures by "opening" after a threshold of failures.

### States

- **CLOSED**: Normal operation (requests pass through)
- **OPEN**: Failing fast (requests rejected immediately)
- **HALF_OPEN**: Testing recovery (limited requests allowed)

### Usage

```asm
; Check if request should proceed
call    Recovery_ShouldAttemptRequest
test    rax, rax
jz      .circuit_open

; Proceed with request...

.circuit_open:
; Circuit breaker is open - fail fast
; Return error to caller immediately
```

## Retry with Exponential Backoff

The system automatically calculates delays between retries:

```
Attempt 1: 100ms delay
Attempt 2: 200ms delay
Attempt 3: 400ms delay
Attempt 4: 800ms delay
Attempt 5: 1600ms delay (capped at 5000ms)
```

### Get Current Retry Delay

```asm
call    Recovery_GetRetryDelay
; RAX = delay in milliseconds
```

## Statistics and Monitoring

### Get Recovery Statistics

```asm
sub     rsp, 64         ; Allocate space for RecoveryStats
lea     rcx, [rsp]
call    Recovery_GetStats

; Access statistics:
; [rsp+0]  = total_requests
; [rsp+8]  = successful_requests
; [rsp+16] = failed_requests
; [rsp+24] = recovered_requests
; [rsp+32] = no_response_count
; [rsp+40] = autopilot_recovery_count
; [rsp+48] = cb_state
; [rsp+52] = fallback_active
; [rsp+53] = autopilot_recovery_active
```

### C/C++ Statistics

```c
RecoveryStats stats;
Recovery_GetStats(&stats);

printf("Success rate: %d%%\n",
    (int)((stats.successful_requests + stats.recovered_requests) * 100 /
          stats.total_requests));

printf("No response count: %llu\n", stats.no_response_count);
printf("Autopilot recoveries: %llu\n", stats.autopilot_recoveries);
```

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0000 | ERR_NONE | Success |
| 0xE001 | ERR_OUT_OF_MEMORY | Memory allocation failed |
| 0xE002 | ERR_MODEL_LOAD_FAILED | Model loading failed |
| 0xE003 | ERR_INFERENCE_TIMEOUT | Inference timed out |
| 0xE004 | ERR_INVALID_INPUT | Invalid input parameters |
| 0xE005 | ERR_KV_CACHE_FULL | KV cache exhausted |
| 0xE006 | ERR_GPU_OOM | GPU out of memory |
| 0xE007 | ERR_NETWORK_TIMEOUT | Network timeout |
| 0xE008 | ERR_WORKER_DIED | Worker process died |
| 0xE009 | ERR_NO_RESPONSE | No response from model/service |
| 0xE00A | ERR_AUTOPILOT_RECOVERY | Autopilot recovered from error |

## Integration Example

### Complete Inference Flow with Error Recovery

```asm
; =============================================================================
; Inference with Full Error Recovery
; RCX = request context
; =============================================================================
InferenceWithRecovery PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .endprolog
    
    mov     rbx, rcx        ; Save request context
    
    ; Check circuit breaker first
    call    Recovery_ShouldAttemptRequest
    test    rax, rax
    jz      .circuit_open
    
    ; Attempt inference with retry
    lea     rcx, DoInference
    mov     rdx, rbx
    call    Recovery_ExecuteWithRetry
    test    rax, rax
    jnz     .success
    
    ; All retries failed - check if it's "no response"
    call    Recovery_GetLastError
    cmp     eax, ERR_NO_RESPONSE
    jne     .regular_failure
    
    ; Handle "no response" with autopilot
    mov     rcx, [rbx].REQUEST.request_id
    call    Recovery_HandleNoResponse
    test    rax, rax
    jz      .autopilot_failed
    
    ; Autopilot is recovering - wait briefly and retry
    mov     ecx, 500        ; 500ms
    call    Sleep
    
    ; Retry one more time
    lea     rcx, DoInference
    mov     rdx, rbx
    call    Recovery_ExecuteWithRetry
    test    rax, rax
    jz      .recovery_failed
    
    ; Success after autopilot recovery
    call    Recovery_AcknowledgeAutopilot
    mov     rax, 1
    jmp     .exit
    
.success:
    mov     rax, 1
    jmp     .exit
    
.circuit_open:
    ; Circuit breaker open - fail fast
    mov     [rbx].REQUEST.error_code, ERR_CIRCUIT_OPEN
    xor     rax, rax
    jmp     .exit
    
.regular_failure:
    ; Regular failure - already logged
    xor     rax, rax
    jmp     .exit
    
.autopilot_failed:
    ; Autopilot couldn't recover
    mov     [rbx].REQUEST.error_code, ERR_AUTOPILOT_FAILED
    xor     rax, rax
    jmp     .exit
    
.recovery_failed:
    ; Recovery attempt failed
    call    Recovery_AcknowledgeAutopilot
    xor     rax, rax
    
.exit:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
DoInference:
    ; Actual inference implementation
    ; RCX = request context
    ; Returns: RAX = 1 success, 0 failure
    ; ...
    ret
    
InferenceWithRecovery ENDP
```

## Testing

Run the test suite:

```powershell
# Build and run tests
.\RawrXD_Error_Recovery_Test_Build.ps1 -Run

# Clean build
.\RawrXD_Error_Recovery_Test_Build.ps1 -Clean -Run
```

### Expected Output

```
RawrXD Error Recovery Test Suite

[TEST 1] Circuit breaker initialization... PASS
[TEST 2] Retry with exponential backoff... PASS
[TEST 3] No response handling... PASS
[TEST 4] Autopilot recovery mode... PASS
[TEST 5] Statistics tracking... PASS

=== Test Summary ===
Passed: 5
Failed: 0

Recovery Statistics:
  Total Requests: 0
  Successful: 0
  Failed: 0
  Recovered: 0
  No Response: 1
  Autopilot Recoveries: 1
  Circuit State: 0
  Fallback Active: 0
  Autopilot Active: 0
```

## Best Practices

1. **Always check circuit breaker** before expensive operations
2. **Configure autopilot** for critical paths that may experience "no response"
3. **Acknowledge autopilot recovery** when you've handled the recovered request
4. **Monitor statistics** to identify patterns in failures
5. **Use appropriate timeouts** - too short causes unnecessary retries, too long delays recovery
6. **Log all recovery events** for post-mortem analysis

## Performance Considerations

- Circuit breaker check: ~5 cycles (negligible)
- Retry delay: Exponential backoff prevents thundering herd
- Autopilot overhead: Minimal - just state tracking
- Statistics: Lock-free updates via atomic operations

## Thread Safety

All recovery functions are thread-safe:
- Circuit breaker state uses atomic operations
- Statistics use lock-free increments
- Autopilot state transitions are atomic

Multiple threads can safely call recovery functions concurrently.
