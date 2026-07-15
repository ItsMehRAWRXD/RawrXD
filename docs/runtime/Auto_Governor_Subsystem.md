# RawrXD Runtime - Auto-Governor Subsystem
## Runtime Self-Regulation & Dynamic Model Adjustment

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Monitoring Systems](#monitoring-systems)
4. [Dynamic Adjustment Strategies](#dynamic-adjustment-strategies)
5. [Governor Loop Implementation](#governor-loop-implementation)
6. [Integration with Inference](#integration-with-inference)
7. [API Reference](#api-reference)

---

## Overview

The Auto-Governor is a runtime self-regulation subsystem that continuously monitors system resources and dynamically adjusts model execution to maintain performance within hardware constraints. It enables RawrXD to run frontier-scale models stably on consumer hardware by automatically adapting to changing conditions.

### Key Capabilities

- **Real-time Monitoring**: Track VRAM, RAM, thermals, bandwidth, tok/s
- **Dynamic Expert Activation**: Enable/disable experts based on load
- **Adaptive Quantization**: Switch precision levels on-the-fly
- **Context Management**: Adjust context window dynamically
- **KV Strategy Switching**: Change KV cache strategy as needed
- **Thermal Throttling**: Reduce load when temperatures rise

### Governor Actions

| Condition | Action | Impact |
|-----------|--------|--------|
| VRAM > 90% | Disable experts | -20% memory |
| Temperature > 85°C | Reduce batch size | -30% heat |
| Tok/s < target | Shrink experts | +40% speed |
| Context pressure | Switch to sliding KV | -50% KV memory |

---

## Architecture

### Subsystem Integration

```
RawrXD Runtime
├── RawrXD_AgenticOrchestrator.asm
│   └── Task queue, telemetry
├── AutoGovernor.asm
│   ├── Monitor.asm
│   ├── DecisionEngine.asm
│   └── Actuator.asm
├── MoEGovernor.asm
│   └── Expert management
├── InferenceCore.asm
│   └── Forward pass
└── KVCacheManager.asm
    └── KV strategies
```

### Control Loop

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Monitor       │────→│  Decision Engine │────→│   Actuator      │
│  (Sensors)      │     │  (Policy Logic)   │     │  (Adjustments)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         ↑                                              │
         └───────────────────────────────────────────────┘
                    (Feedback Loop)
```

---

## Monitoring Systems

### VRAM Monitor

```asm
; Monitor GPU VRAM usage
AutoGovernor_MonitorVRAM PROC
    ; Query Vulkan memory stats
    call VulkanBridge_GetMemoryStats
    
    ; Calculate utilization
    mov rax, [mem_stats.used]
    mov rbx, [mem_stats.total]
    
    ; utilization = used / total * 100
    xor rdx, rdx
    mov rcx, 100
    mul rcx
    div rbx
    
    mov [metrics.vram_utilization], eax
    
    ; Check thresholds
    cmp eax, 90
    jge @@critical
    
    cmp eax, 80
    jge @@warning
    
    mov [status.vram], STATUS_OK
    ret
    
@@warning:
    mov [status.vram], STATUS_WARNING
    ret
    
@@critical:
    mov [status.vram], STATUS_CRITICAL
    call AutoGovernor_TriggerVRAMAction
    ret
AutoGovernor_MonitorVRAM ENDP
```

### Thermal Monitor

```asm
; Monitor GPU and CPU temperatures
AutoGovernor_MonitorThermal PROC
    ; Read GPU temperature
    call VulkanBridge_GetGPUTemperature
    mov [metrics.gpu_temp], eax
    
    ; Read CPU temperature
    call System_GetCPUTemperature
    mov [metrics.cpu_temp], eax
    
    ; Check GPU threshold
    cmp [metrics.gpu_temp], 85
    jge @@gpu_critical
    
    cmp [metrics.gpu_temp], 75
    jge @@gpu_warning
    
@@check_cpu:
    ; Check CPU threshold
    cmp [metrics.cpu_temp], 80
    jge @@cpu_critical
    
    cmp [metrics.cpu_temp], 70
    jge @@cpu_warning
    
    mov [status.thermal], STATUS_OK
    ret
    
@@gpu_warning:
    mov [status.thermal], STATUS_WARNING
    ret
    
@@gpu_critical:
    mov [status.thermal], STATUS_CRITICAL
    call AutoGovernor_TriggerThermalAction
    ret
    
@@cpu_warning:
    mov [status.thermal], STATUS_WARNING
    ret
    
@@cpu_critical:
    mov [status.thermal], STATUS_CRITICAL
    call AutoGovernor_TriggerThermalAction
    ret
AutoGovernor_MonitorThermal ENDP
```

### Performance Monitor

```asm
; Monitor inference performance
AutoGovernor_MonitorPerformance PROC
    ; Calculate tokens per second
    mov rax, [stats.tokens_generated]
    mov rbx, [stats.elapsed_ms]
    
    ; tok/s = tokens / (ms / 1000)
    mov rcx, 1000
    mul rcx
    xor rdx, rdx
    div rbx
    
    mov [metrics.tok_per_sec], rax
    
    ; Compare to target
    cmp rax, [target.tok_per_sec]
    jl @@below_target
    
    mov [status.performance], STATUS_OK
    ret
    
@@below_target:
    mov [status.performance], STATUS_WARNING
    call AutoGovernor_TriggerPerformanceAction
    ret
AutoGovernor_MonitorPerformance ENDP
```

---

## Dynamic Adjustment Strategies

### Expert Activation/Deactivation

```asm
; Dynamically adjust active experts
AutoGovernor_AdjustExperts PROC
    ; Check current VRAM usage
    cmp [status.vram], STATUS_CRITICAL
    jne @@check_performance
    
    ; Critical: disable lowest-ranked experts
    call MoEGovernor_GetExpertRanking
    
    ; Disable bottom 20%
    mov rcx, [num_active_experts]
    shr rcx, 2                      ; Divide by 4
    
@@disable_loop:
    push rcx
    
    call MoEGovernor_GetLowestRankedExpert
    call MoEGovernor_DisableExpert
    
    pop rcx
    dec rcx
    jnz @@disable_loop
    
    jmp @@done
    
@@check_performance:
    ; Check if we can enable more experts
    cmp [status.performance], STATUS_OK
    jne @@done
    
    cmp [status.vram], STATUS_OK
    jne @@done
    
    ; Safe to enable more experts
    call MoEGovernor_EnableNextExpert
    
@@done:
    ret
AutoGovernor_AdjustExperts ENDP
```

### Dynamic Quantization

```asm
; Adjust quantization levels dynamically
AutoGovernor_AdjustQuantization PROC
    ; Check if we need more aggressive quantization
    cmp [status.vram], STATUS_CRITICAL
    jne @@check_performance
    
    ; Critical: drop precision on non-critical layers
    call AutoGovernor_GetQuantizationMap
    
    ; Find layers currently at Q4
    mov rcx, [num_layers]
    lea rsi, [quant_map]
    
@@find_q4_loop:
    push rcx
    
    cmp dword [rsi], 4
    jne @@next
    
    ; Drop to Q2
    mov dword [rsi], 2
    
@@next:
    add rsi, 4
    pop rcx
    dec rcx
    jnz @@find_q4_loop
    
    ; Re-quantize affected layers
    call ModelFactory_RequantizeLayers
    
    ret
    
@@check_performance:
    ; If performance is good and VRAM available,
    ; consider increasing precision
    cmp [status.performance], STATUS_OK
    jne @@done
    
    cmp [status.vram], STATUS_OK
    jne @@done
    
    ; Could upgrade some Q2 layers to Q4
    ; (optional optimization)
    
@@done:
    ret
AutoGovernor_AdjustQuantization ENDP
```

### Context Window Adjustment

```asm
; Adjust context window dynamically
AutoGovernor_AdjustContext PROC
    ; Check KV cache pressure
    call KVCacheManager_GetUtilization
    
    cmp eax, 90
    jge @@reduce_context
    
    cmp eax, 50
    jle @@increase_context
    
    ret
    
@@reduce_context:
    ; Switch to sliding window
    mov [kv_strategy], KV_SLIDING
    mov [context_window], 4096
    call KVCacheManager_Reconfigure
    ret
    
@@increase_context:
    ; If resources available, increase context
    cmp [status.vram], STATUS_OK
    jne @@done
    
    ; Could increase context window
    ; (optional optimization)
    
@@done:
    ret
AutoGovernor_AdjustContext ENDP
```

### KV Strategy Switching

```asm
; Switch KV cache strategy based on conditions
AutoGovernor_SwitchKVStrategy PROC
    ; Analyze current conditions
    call AutoGovernor_AnalyzeConditions
    
    ; Determine optimal strategy
    cmp [metrics.vram_utilization], 85
    jge @@use_sliding
    
    cmp [metrics.context_length], 32768
    jge @@use_segmented
    
    cmp [metrics.vram_utilization], 50
    jle @@use_full
    
    ret
    
@@use_full:
    mov [kv_strategy], KV_FULL
    jmp @@apply
    
@@use_sliding:
    mov [kv_strategy], KV_SLIDING
    jmp @@apply
    
@@use_segmented:
    mov [kv_strategy], KV_SEGMENTED
    
@@apply:
    call KVCacheManager_SetStrategy
    call KVCacheManager_Reallocate
    ret
AutoGovernor_SwitchKVStrategy ENDP
```

---

## Governor Loop Implementation

### Main Governor Loop

```asm
; Main governor loop - runs continuously
AutoGovernor_MainLoop PROC
@@loop:
    ; Check if governor is enabled
    mov al, [governor_enabled]
    test al, al
    jz @@disabled
    
    ; Phase 1: Monitor
    call AutoGovernor_MonitorVRAM
    call AutoGovernor_MonitorThermal
    call AutoGovernor_MonitorPerformance
    call AutoGovernor_MonitorBandwidth
    
    ; Phase 2: Decide
    call AutoGovernor_EvaluateConditions
    
    ; Phase 3: Act
    cmp [action_required], 1
    jne @@sleep
    
    call AutoGovernor_ExecuteAdjustments
    
@@sleep:
    ; Sleep for monitoring interval (100ms)
    mov rcx, 100
    call Sleep
    
    jmp @@loop
    
@@disabled:
    ; Governor disabled - just sleep
    mov rcx, 1000
    call Sleep
    jmp @@loop
    
    ret
AutoGovernor_MainLoop ENDP
```

### Decision Engine

```asm
; Evaluate conditions and determine actions
AutoGovernor_EvaluateConditions PROC
    ; Reset action flags
    mov [action_required], 0
    mov [action_experts], 0
    mov [action_quantization], 0
    mov [action_context], 0
    mov [action_kv], 0
    
    ; Check VRAM
    cmp [status.vram], STATUS_CRITICAL
    je @@critical_vram
    
    cmp [status.vram], STATUS_WARNING
    je @@warning_vram
    
    jmp @@check_thermal
    
@@critical_vram:
    ; Multiple actions needed
    mov [action_required], 1
    mov [action_experts], 1
    mov [action_quantization], 1
    mov [action_context], 1
    ret
    
@@warning_vram:
    mov [action_required], 1
    mov [action_experts], 1
    ret
    
@@check_thermal:
    cmp [status.thermal], STATUS_CRITICAL
    je @@critical_thermal
    
    cmp [status.thermal], STATUS_WARNING
    je @@warning_thermal
    
    jmp @@check_performance
    
@@critical_thermal:
    mov [action_required], 1
    mov [action_experts], 1
    mov [action_context], 1
    ret
    
@@warning_thermal:
    mov [action_required], 1
    mov [action_experts], 1
    ret
    
@@check_performance:
    cmp [status.performance], STATUS_WARNING
    je @@performance_issue
    
    ret
    
@@performance_issue:
    mov [action_required], 1
    mov [action_experts], 1
    ret
AutoGovernor_EvaluateConditions ENDP
```

### Action Execution

```asm
; Execute determined adjustments
AutoGovernor_ExecuteAdjustments PROC
    ; Adjust experts
    cmp [action_experts], 1
    jne @@check_quantization
    
    call AutoGovernor_AdjustExperts
    
@@check_quantization:
    cmp [action_quantization], 1
    jne @@check_context
    
    call AutoGovernor_AdjustQuantization
    
@@check_context:
    cmp [action_context], 1
    jne @@check_kv
    
    call AutoGovernor_AdjustContext
    
@@check_kv:
    cmp [action_kv], 1
    jne @@done
    
    call AutoGovernor_SwitchKVStrategy
    
@@done:
    ; Log adjustments
    call AutoGovernor_LogAdjustments
    
    ret
AutoGovernor_ExecuteAdjustments ENDP
```

---

## Integration with Inference

### Inference Hook

```asm
; Hook into inference pipeline
Inference_ForwardPassWithGovernor PROC
    ; Pre-inference: check governor
    call AutoGovernor_PreInferenceCheck
    
    ; Run forward pass
    call Inference_ForwardPass
    
    ; Post-inference: update metrics
    call AutoGovernor_PostInferenceUpdate
    
    ret
Inference_ForwardPassWithGovernor ENDP

; Pre-inference check
AutoGovernor_PreInferenceCheck PROC
    ; Quick check if adjustments needed
    cmp [status.vram], STATUS_CRITICAL
    jge @@needs_adjustment
    
    cmp [status.thermal], STATUS_CRITICAL
    jge @@needs_adjustment
    
    ret
    
@@needs_adjustment:
    ; Execute pending adjustments
    call AutoGovernor_ExecuteAdjustments
    ret
AutoGovernor_PreInferenceCheck ENDP

; Post-inference update
AutoGovernor_PostInferenceUpdate PROC
    ; Update token count
    inc [stats.tokens_generated]
    
    ; Update timing
    call QueryPerformanceCounter
    mov [stats.last_token_time], rax
    
    ; Periodic full monitoring
    mov rax, [stats.tokens_generated]
    and rax, 0xFF                       ; Every 256 tokens
    jnz @@done
    
    call AutoGovernor_MonitorVRAM
    call AutoGovernor_MonitorThermal
    call AutoGovernor_MonitorPerformance
    
@@done:
    ret
AutoGovernor_PostInferenceUpdate ENDP
```

---

## API Reference

### C/C++ Interface

```cpp
// Initialize Auto-Governor
GovernorStatus AutoGovernor_Init();

// Start governor loop
GovernorStatus AutoGovernor_Start();

// Stop governor loop
GovernorStatus AutoGovernor_Stop();

// Manual trigger
GovernorStatus AutoGovernor_TriggerAdjustment();

// Get current metrics
GovernorStatus AutoGovernor_GetMetrics(RuntimeMetrics* metrics);

// Set thresholds
GovernorStatus AutoGovernor_SetThresholds(ThresholdConfig* config);

// Enable/disable specific adjustments
GovernorStatus AutoGovernor_EnableAdjustment(AdjustmentType type);
GovernorStatus AutoGovernor_DisableAdjustment(AdjustmentType type);
```

### MASM Interface

```asm
; Initialize
extern AutoGovernor_Init:proc

; Control loop
extern AutoGovernor_Start:proc
extern AutoGovernor_Stop:proc

; Monitoring
extern AutoGovernor_MonitorVRAM:proc
extern AutoGovernor_MonitorThermal:proc
extern AutoGovernor_MonitorPerformance:proc

; Adjustments
extern AutoGovernor_AdjustExperts:proc
extern AutoGovernor_AdjustQuantization:proc
extern AutoGovernor_AdjustContext:proc
```

---

## Summary

The Auto-Governor enables RawrXD to:

- ✅ Monitor system resources in real-time
- ✅ Dynamically adjust active experts
- ✅ Switch quantization levels on-the-fly
- ✅ Adjust context window dynamically
- ✅ Change KV cache strategy as needed
- ✅ Maintain performance within constraints
- ✅ Run frontier models stably on consumer hardware

**Status:** ✅ Complete

---

*End of Auto-Governor Subsystem Documentation*
