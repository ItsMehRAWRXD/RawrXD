# MoE Capability Recovery Toolkit

A complete toolkit for recovering all capabilities from your pure x64 MASM MoE system.

## What This Does

Your MoE system has emergent behaviors ("swarm", "ghost text", "etcetras") that you may have forgotten. This toolkit helps you:

1. **Extract** all strings, exports, and code patterns from your binary
2. **Instrument** your code with tracing macros
3. **Log** every router decision, expert activation, and emergent behavior
4. **Map** the complete capability surface of your system

## Quick Start

### Step 1: Extract Static Capabilities

```powershell
# Run the extraction tool on your MoE binary
.\ExtractCapabilities.ps1 -BinaryPath "C:\path\to\your\MoE.exe" -OutputDir ".\recovery" -DeepAnalysis
```

This creates:
- `strings_dump.txt` - All strings in your binary
- `capability_strings.txt` - Filtered capability-related strings
- `exports_dump.txt` - All exported functions
- `code_patterns.txt` - Router/expert dispatch patterns
- `capability_map.txt` - Human-readable capability summary

### Step 2: Instrument Your Code

Add tracing to your MASM source:

```asm
; At the top of your main ASM file
INCLUDE TraceMacros.inc

; In your router
MyRouter PROC
    TRACE_ROUTER_ENTRY 0
    
    ; ... router logic ...
    
    ; Select expert
    mov expert_id, rax
    TRACE_ROUTER_EXIT 0, expert_id
    ret
MyRouter ENDP

; In your expert activation
ActivateExpert PROC
    mov expert_id, rcx
    mov confidence, rdx
    TRACE_EXPERT_ACTIVATE expert_id, confidence
    
    ; ... expert logic ...
    ret
ActivateExpert ENDP
```

### Step 3: Build with Tracing

```batch
; Assemble with RECOVERY_MODE defined
ml64 your_moe.asm /DRECOVERY_MODE /link /subsystem:console

; Link with TraceLogger
link your_moe.obj TraceLogger.obj /out:MoE_Traced.exe
```

### Step 4: Run and Capture

```batch
; Run your instrumented binary
MoE_Traced.exe

; The trace log will be created: moe_trace.log
```

### Step 5: Analyze the Trace

The log format:
```
[TIMESTAMP] ROUTER router_id=0 expert=5
[TIMESTAMP] EXPERT id=5 confidence=847
[TIMESTAMP] SWARM_MODE experts=3 swarm_id=1
[TIMESTAMP] GHOST_TEXT token=42 expert=7
```

## Understanding Your MoE System

### Router Patterns to Look For

1. **Direct Dispatch**: Router selects one expert
   ```
   ROUTER -> EXPERT (confidence=X)
   ```

2. **Swarm Mode**: Multiple experts activate simultaneously
   ```
   ROUTER -> SWARM_MODE (experts=N)
   EXPERT (id=X)
   EXPERT (id=Y)
   EXPERT (id=Z)
   MERGE (branches=3)
   ```

3. **Ghost Text**: Speculative generation
   ```
   ROUTER -> GHOST_TEXT (token=X)
   EXPERT (id=Y) [ghost]
   ```

4. **Shadow Routing**: Fallback when primary fails
   ```
   ROUTER -> SHADOW_ROUTE (primary=X, fallback=Y)
   ```

5. **Latent Experts**: Activate only under specific conditions
   ```
   [many normal operations]
   LATENT_EXPERT (id=X, trigger=condition)
   ```

### Expert Types to Identify

From your trace logs, categorize experts by behavior:

| Expert ID | Activation Pattern | Likely Type |
|-----------|---------------------|-------------|
| 0-3 | Always active | Core reasoning |
| 4-7 | High confidence (>800) | Specialized |
| 8-11 | Only with specific tokens | Latent |
| 12-15 | Multiple per token | Swarm members |
| 16-19 | Speculative branches | Ghost/Prefetch |
| 20+ | Rare, conditional | Experimental |

## Advanced Recovery

### Finding Hidden Features

Search your strings dump for:

```powershell
# Experimental features
Select-String -Path "recovery\strings_dump.txt" -Pattern "experimental|hidden|unsafe|internal|debug"

# Mode switches
Select-String -Path "recovery\strings_dump.txt" -Pattern "mode_|enable_|disable_|toggle_"

# Special experts
Select-String -Path "recovery\strings_dump.txt" -Pattern "expert_|special_|latent_|shadow_"

# Capabilities
Select-String -Path "recovery\strings_dump.txt" -Pattern "cap_|feature_|ability_"
```

### Reconstructing the Jump Table

If you have IDA Pro or Ghidra:

1. Load your binary
2. Find the router function
3. Look for large tables of addresses (jump tables)
4. Each entry = one expert dispatch target
5. Count entries = number of experts

### Mapping Expert Relationships

From trace logs:

```powershell
# Find which experts often activate together
Get-Content moe_trace.log | 
    Select-String "EXPERT id=(\d+)" | 
    Group-Object { $_.Matches[0].Groups[1].Value } |
    Sort-Object Count -Descending
```

## Building the Capability Atlas

Once you have traces, create:

```
MoE Capability Atlas
==================

Expert 0: Core reasoning (always active)
  - Confidence: 600-900
  - Tokens: all types
  - Latency: low

Expert 1: Code generation
  - Confidence: 700-950
  - Tokens: code, brackets, semicolons
  - Latency: medium

Expert 2: Ghost text (speculative)
  - Confidence: 400-600
  - Tokens: next-token prediction
  - Latency: high (speculative)

Expert 3: Swarm coordinator
  - Confidence: 500-800
  - Activates: Experts 4, 5, 6
  - Latency: high (parallel)

Expert 4-6: Swarm members
  - Activated by: Expert 3
  - Merge strategy: weighted average

Expert 7: Latent (math)
  - Trigger: digits, operators
  - Confidence: 800-1000
  - Latency: medium

Expert 8: Shadow fallback
  - Trigger: primary expert confidence < 300
  - Confidence: 400-700
  - Latency: low

... etc
```

## Files in This Toolkit

| File | Purpose |
|------|---------|
| `ExtractCapabilities.ps1` | Extract strings, exports, patterns from binary |
| `TraceMacros.inc` | MASM macros for instrumenting your code |
| `TraceLogger.asm` | Logging infrastructure (build as DLL) |
| `README.md` | This file |

## Tips

1. **Start with static analysis** - Run ExtractCapabilities.ps1 first
2. **Instrument gradually** - Add tracing to one module at a time
3. **Run comprehensive tests** - Exercise all code paths
4. **Correlate with source** - Match trace patterns to your ASM
5. **Document as you go** - Build the capability atlas incrementally

## Troubleshooting

### No strings found
- Your binary might be packed or encrypted
- Try running on the unpacked binary

### No exports found
- Your binary might not have an export table
- Look for internal symbols in your ASM source

### Trace log is empty
- Make sure RECOVERY_MODE is defined during assembly
- Check that TraceLogger.dll is loaded
- Verify file permissions for moe_trace.log

### Too much trace data
- Focus on specific modules
- Use conditional tracing (trace only certain experts)
- Increase buffer sizes in TraceLogger.asm

## Next Steps

Once you've recovered all capabilities:

1. **Document** everything in the capability atlas
2. **Optimize** based on activation patterns
3. **Extend** with new experts for missing capabilities
4. **Test** edge cases and boundary conditions
5. **Archive** the recovery data for future reference

## Support

This toolkit is designed for pure x64 MASM MoE systems with no dependencies.

If your system uses external libraries, you may need to adapt the extraction tools.
