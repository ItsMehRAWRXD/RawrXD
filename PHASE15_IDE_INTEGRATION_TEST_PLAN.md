# Phase 15: IDE Integration - Test Case 1: Streaming Ghost Text

## Test Objective

Validate the complete integration pipeline: **RawrXD IDE → Sovereign Engine → 7B Model → Streaming Response → Ghost Text Display**

This is the "Hello World" of AI coding assistants - if this works, the foundation is solid.

---

## Test Specification

### Test Name
`TC15_001_StreamingGhostText_Basic`

### Prerequisites
- [ ] RawrXD IDE built with Sovereign ABI bindings
- [ ] 7B Q4_K model MMAP'd and ready
- [ ] Named Pipe IPC bridge active
- [ ] Tokenizer loaded (Trie-based)

### Test Input
**File**: `test_sample.cpp`
**Cursor Position**: Line 15, Column 12 (inside function body)
**Trigger**: User types `// Calculate fibon` and pauses

```cpp
// test_sample.cpp
#include <vector>
#include <iostream>

class MathUtils {
public:
    // Calculate fibon    <-- CURSOR HERE (user just typed this)
    
};

int main() {
    MathUtils math;
    return 0;
}
```

### Expected Behavior

1. **Trigger Detection** (0-10ms)
   - IDE detects pause after typing
   - Context buffer captured (current file + cursor position)

2. **IPC Dispatch** (10-20ms)
   - Context serialized to Named Pipe
   - Sovereign_Engine receives request

3. **Tokenization** (20-50ms)
   - Trie tokenizer encodes context
   - ~50 tokens generated

4. **Inference** (100-500ms for first token)
   - KV cache lookup (Q4_K)
   - Forward pass through model
   - Top-P sampling with temperature 0.7

5. **Streaming Response** (50-100ms per subsequent token)
   - Tokens generated incrementally
   - Each token sent back via IPC

6. **Ghost Text Display** (10-20ms per update)
   - IDE receives token stream
   - Ghost text rendered in gray after cursor
   - Smooth animation (no flicker)

### Expected Output

**Ghost Text Suggestion** (displayed in gray):
```cpp
    // Calculate fibonacci sequence up to n terms
    std::vector<int> fibonacci(int n) {
        std::vector<int> result;
        if (n <= 0) return result;
        result.push_back(0);
        if (n == 1) return result;
        result.push_back(1);
        for (int i = 2; i < n; ++i) {
            result.push_back(result[i-1] + result[i-2]);
        }
        return result;
    }
```

---

## Success Criteria

### Latency Requirements
| Phase | Target | Maximum | Measurement |
|-------|--------|---------|-------------|
| Trigger → First Token | <200ms | <500ms | `Sovereign_Telemetry` |
| Token-to-Token | <100ms | <200ms | `Sovereign_Telemetry` |
| Total Suggestion Time | <2s | <5s | Stopwatch |
| Ghost Text Update | <16ms | <33ms | IDE render loop |

### Quality Requirements
- [ ] Suggestion is syntactically valid C++
- [ ] Suggestion is semantically appropriate (Fibonacci function)
- [ ] No hallucinated APIs (only std::vector, standard C++)
- [ ] Proper indentation matching file style

### Stability Requirements
- [ ] No crashes during 100 consecutive triggers
- [ ] Memory usage stable (no leaks)
- [ ] IPC pipe remains connected
- [ ] Model stays loaded (no reloads)

---

## Test Procedure

### Step 1: Environment Setup
```powershell
# 1. Start RawrXD IDE with Sovereign integration
D:\RawrXD\RawrXD-Win32IDE.exe --sovereign-engine=D:\RawrXD\Sovereign_Final.exe

# 2. Verify Named Pipe created
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like "*Sovereign*" }

# 3. Check MMAP status
# (In IDE console) Sovereign_MMAP_GetStats()
```

### Step 2: Trigger Test
1. Open `test_sample.cpp`
2. Navigate to line 15
3. Type `// Calculate fibon`
4. Pause for 500ms
5. Observe ghost text appearance

### Step 3: Validation
```cpp
// Verify in Sovereign_Telemetry.log:
[2026-06-29T10:15:32.145Z] INFO: IPC_Request_Received (size: 1,247 bytes)
[2026-06-29T10:15:32.167Z] INFO: Tokenization_Complete (tokens: 52)
[2026-06-29T10:15:32.298Z] INFO: First_Token_Generated (latency: 153ms)
[2026-06-29T10:15:32.412Z] INFO: Token_Stream_Progress (token: 5/45)
...
[2026-06-29T10:15:34.891Z] INFO: Generation_Complete (total_tokens: 45, total_time: 2.746s)
```

### Step 4: Stress Test
```powershell
# Automated stress test
for ($i = 0; $i -lt 100; $i++) {
    # Trigger completion
    Send-Keys "// Test $i "
    Start-Sleep -Milliseconds 500
    
    # Check for ghost text
    $ghostText = Get-GhostText
    if ($ghostText -eq $null) {
        Write-Error "FAILED: No ghost text on iteration $i"
        break
    }
    
    # Clear and continue
    Send-Keys "{ESC}"
    Start-Sleep -Milliseconds 100
}
```

---

## Failure Modes & Mitigation

### Failure 1: High First-Token Latency (>500ms)
**Symptoms**: Ghost text appears after long delay
**Diagnosis**: Check `Sovereign_Telemetry` for:
- Cold KV cache (first inference after load)
- Page faults during weight access (MMAP not prefetched)
- IPC serialization overhead

**Mitigation**:
- Pre-warm model with dummy inference on startup
- Ensure critical layers prefetched
- Optimize IPC buffer size

### Failure 2: Stuttering Ghost Text
**Symptoms**: Ghost text updates in chunks, not smoothly
**Diagnosis**: 
- Token generation slower than display rate
- IPC buffer underrun

**Mitigation**:
- Implement token buffering (batch 3-5 tokens)
- Increase generation temperature for faster sampling
- Use speculative decoding

### Failure 3: Memory Growth
**Symptoms**: IDE memory usage increases with each completion
**Diagnosis**: 
- KV cache not being cleared between sessions
- IPC buffers accumulating
- Ghost text DOM nodes not freed

**Mitigation**:
- Implement KV cache rotation
- Add IPC buffer pooling
- Verify DOM cleanup in IDE

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      RawrXD IDE                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Text Editor  │  │ Ghost Text   │  │ IPC Client       │  │
│  │ (Cursor      │  │ Renderer     │  │ (Named Pipe)     │  │
│  │  Position)   │  │              │  │                  │  │
│  └──────┬───────┘  └──────▲───────┘  └────────┬─────────┘  │
│         │                  │                    │            │
│         │ 1. Trigger       │ 6. Render          │ 2. Send    │
│         │    Event         │    Ghost Text      │    Request │
│         │                  │                    │            │
│         └──────────────────┴────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ Named Pipe: \\.\pipe\SovereignIPC
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Sovereign Engine                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ IPC Server   │  │ Tokenizer    │  │ Inference        │  │
│  │ (Named Pipe) │  │ (Trie)       │  │ (7B Q4_K Model)  │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │            │
│         │ 3. Receive    │ 4. Tokenize        │ 5. Generate │
│         │    Request      │    Context         │    Tokens   │
│         └─────────────────┴────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

---

## Telemetry Points

Add these metrics to `Sovereign_Telemetry`:

```cpp
struct GhostTextTelemetry {
    uint64_t trigger_timestamp;      // When user paused typing
    uint64_t first_token_timestamp;  // When first token generated
    uint64_t complete_timestamp;     // When generation finished
    uint32_t context_tokens;         // Tokens in context
    uint32_t generated_tokens;       // Tokens generated
    float avg_token_latency_ms;      // Average time per token
    float peak_memory_mb;            // Peak RAM during inference
    bool was_accepted;               // Did user accept suggestion?
};
```

---

## Next Test Cases

After TC15_001 passes:

### TC15_002: Multi-Line Context
**Input**: Function with 50 lines of context above cursor
**Goal**: Validate context window handling (4K tokens)

### TC15_003: Language Switching
**Input**: Python file instead of C++
**Goal**: Validate language-specific tokenization

### TC15_004: Concurrent Completions
**Input**: Two editors open, both trigger simultaneously
**Goal**: Validate thread safety and resource sharing

### TC15_005: Long-Running Session
**Input**: IDE open for 8 hours, periodic completions
**Goal**: Validate memory stability over time

---

## Sign-Off Criteria

This test case is **COMPLETE** when:

- [ ] TC15_001 executes successfully 100/100 times
- [ ] Average first-token latency <200ms
- [ ] No memory leaks detected
- [ ] Ghost text renders smoothly (60 FPS)
- [ ] User acceptance rate >80% (measured via telemetry)

**Ready for Production**: After all TC15 tests pass
