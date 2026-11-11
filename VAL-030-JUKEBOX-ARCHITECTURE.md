# VAL-030 Jukebox Architecture

## The Mechanical Heart of B008

The Jukebox is the **execution-oriented streaming layer** that transforms the B008 concept from theory to reality.

### Architecture Overview

```
B008 Image (800B model)
    |
    v
Tensor Residency Planner (DJ - decides what to play)
    |
    v
Dependency Queue (playlist - ordered by priority)
    |
    v
Jukebox Streamer (mechanism - IOCP + Triple Buffer)
    |
    +----------------+----------------+
    |                                 |
    v                                 v
IOCP Worker Thread              Triple Buffer
GetQueuedCompletionStatus       Compute / Ready / Loading
    |                                 |
    v                                 v
NVMe Async Read                 AVX-512 Kernel
```

### Key Inversion Complete

| Old Model | B008 Model |
|-----------|------------|
| "Load model, then run" | "Model is performed, never loaded" |
| Layer-level (5GB) | Block-level (256MB) |
| Synchronous read | Async IOCP |
| Compute waits for IO | IO feeds compute pipeline |

## Components

### 1. B008 Format (`b008_format.hpp`)

The execution format. Not GGUF. Not storage. **Execution-oriented.**

```cpp
struct Block {
    uint64_t tensor_id;
    uint64_t block_id;
    uint64_t file_offset;
    BlockState state;  // COLD -> LOADING -> READY -> COMPUTING -> EVICTING
    uint64_t ram_address;
};
```

**Key insight:** The Jukebox doesn't know tensors. It knows blocks.

### 2. Triple Buffer

Three-slot rotation for continuous streaming:

```
Buffer A: COMPUTING (current kernel)
Buffer B: READY (prefetched, waiting)
Buffer C: LOADING (IO in progress)

Pipeline:
1. Execute on A
2. B already ready
3. C loading next
4. Rotate: A->Empty, B->Compute, C->Ready
5. Start loading into A
```

**Size:** 256MB × 3 = 768MB (not the cache, just the pipeline)

### 3. Dependency Queue

Priority-ordered queue from the Residency Planner:

```cpp
struct Entry {
    uint64_t block_id;
    uint32_t priority;    // Higher = more urgent
    uint64_t kernel_id;   // Which kernel needs this
};
```

**Priority scheme:**
- 100: Next kernel (immediate need)
- 80: Lookahead 1 (prefetch)
- 60: Lookahead 2 (speculative)
- 40: Lookahead 3 (very speculative)

### 4. IOCP Worker (MASM)

Dependency-free Win32 worker:

```asm
JukeboxWorkerAsm:
.loop:
    call GetQueuedCompletionStatus    ; Block until IO completes
    call MarkBlockReady               ; Update residency table
    call IssueNextRequest             ; Queue next read
    jmp .loop
```

**No spinning. No polling. Event-driven.**

## Execution Flow

```
Kernel Start (Attention Q)
    |
    v
Planner: "Need blocks for Q projection"
    |
    v
DependencyQueue.Enqueue(block_id=100, priority=100)
    |
    v
Jukebox: IssueAsyncRead(block 100)
    |
    v
IOCP: NVMe read in progress
    |
    v
[Compute continues on previous kernel]
    |
    v
IOCP Completion: Block 100 ready
    |
    v
TripleBuffer: Mark slot as READY
    |
    v
Next kernel: AcquireComputeSlot() -> Block 100
    |
    v
Execute AVX-512 kernel
```

## VAL-030.1 Certification Gates

### Gate 1: Zero Buffer Starvation

```
Metric: buffer_starvations
Target: 0
```

**Pass:** Compute never waits for IO.

### Gate 2: Queue Saturation

```
Metric: avg_queue_depth
Target: > 0 (always have work in flight)
```

**Pass:** IOCP always has pending reads.

### Gate 3: Completion Rate

```
Metric: completed / submitted
Target: > 95%
```

**Pass:** Almost all requests complete successfully.

### Gate 4: Latency Masking

```
Metric: io_latency_p99 vs kernel_execution_time
Target: io_latency < kernel_time / 2
```

**Pass:** Triple buffer hides IO latency.

## Build Commands

```powershell
# Build VAL-030.1
.\build_jukebox.ps1

# Build and run tests
.\build_jukebox.ps1 -RunTests

# Manual test
bin\test_jukebox.exe 100 256    # 100 blocks, 256MB each
```

## Files Created

| File | Purpose |
|------|---------|
| `b008_format.hpp` | B008 execution format definitions |
| `jukebox.hpp/cpp` | Jukebox control and triple buffer |
| `jukebox.asm` | MASM IOCP worker (optional) |
| `test_jukebox_stream.cpp` | Validation harness |
| `build_jukebox.ps1` | Build automation |

## Next Steps

1. **Build VAL-030.1**: Run `build_jukebox.ps1 -RunTests`
2. **Phase 1**: Connect to 70B model (resident path)
3. **Phase 2**: Test 200B streaming (validate no stalls)
4. **Phase 3**: Full 800B B008 execution

## The B008 Inversion

**Not:** "How do I fit 800B into 48GB?"

**But:** "How do I stream 800B through 48GB?"

The Jukebox makes this real. The model is no longer loaded. The model is **performed**.

---

*VAL-030.1 Status: Implementation Complete*
*Next: Build & Validate*
