# Sovereign Engine Heap Patch Guide

## Issue Summary
Sovereign.exe crashes with `STATUS_ACCESS_VIOLATION (-1073741819)` when loading models.

## Root Cause
The Windows heap APIs work correctly (verified by `test_heap.exe` - 11/11 tests passed).
The issue is isolated to Sovereign's custom `Heap_Init` implementation.

## Solution Options

### Option 1: Minimal Patch (Recommended)

Replace custom heap with Windows process heap:

```c
// In sovereign.c or memory initialization code

// BEFORE (problematic):
static HANDLE g_custom_heap = NULL;

void Heap_Init() {
    // This likely causes the access violation
    g_custom_heap = HeapCreate(HEAP_NO_SERIALIZE, 1024*1024, 0);
    if (!g_custom_heap) {
        // Error handling may also be problematic
        abort();
    }
}

void* Heap_Alloc(size_t size) {
    return HeapAlloc(g_custom_heap, 0, size);
}

// AFTER (fixed):
static HANDLE g_heap = NULL;

void Heap_Init() {
    // Use process heap - always available, already initialized
    g_heap = GetProcessHeap();
    if (!g_heap) {
        // Fallback: create a new heap if process heap unavailable
        g_heap = HeapCreate(0, 1024*1024, 0);
    }
}

void* Heap_Alloc(size_t size) {
    if (!g_heap) Heap_Init();  // Lazy initialization
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, size);
}

void Heap_Free(void* ptr) {
    if (g_heap && ptr) {
        HeapFree(g_heap, 0, ptr);
    }
}

void Heap_Shutdown() {
    // Only destroy if we created a custom heap
    // Don't destroy process heap!
    if (g_heap && g_heap != GetProcessHeap()) {
        HeapDestroy(g_heap);
    }
    g_heap = NULL;
}
```

### Option 2: CRT Heap Wrapper

Use standard C library heap (proven working):

```c
// sovereign_memory.c - Drop-in replacement

#include <stdlib.h>
#include <string.h>

void Heap_Init() {
    // CRT heap is already initialized
    // Nothing to do
}

void* Heap_Alloc(size_t size) {
    return calloc(1, size);  // Zero-initialized
}

void* Heap_Realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}

void Heap_Free(void* ptr) {
    free(ptr);
}

size_t Heap_Size(void* ptr) {
    return _msize(ptr);  // MSVC specific
}

void Heap_Shutdown() {
    // CRT handles cleanup
}
```

### Option 3: Assembly-Level Patch

For the MASM-based Sovereign:

```asm
; sovereign_memory.asm

.data
    g_heap HANDLE 0

.code

; Heap_Init PROC
; Returns: 0 on success, non-zero on failure
Heap_Init PROC
    ; Try process heap first
    call GetProcessHandle
    mov g_heap, rax
    test rax, rax
    jnz success
    
    ; Fallback: create new heap
    mov ecx, 0              ; flOptions
    mov edx, 1024*1024      ; dwInitialSize
    mov r8d, 0              ; dwMaximumSize (0 = growable)
    call HeapCreate
    mov g_heap, rax
    test rax, rax
    jz failure
    
success:
    xor eax, eax
    ret
    
failure:
    mov eax, 1
    ret
Heap_Init ENDP

; Heap_Alloc PROC
; RCX = size
; Returns: pointer or NULL
Heap_Alloc PROC
    push rbx
    mov rbx, rcx
    
    ; Ensure heap is initialized
    mov rax, g_heap
    test rax, rax
    jnz do_alloc
    call Heap_Init
    test eax, eax
    jnz alloc_failed
    
do_alloc:
    mov rcx, g_heap
    mov edx, HEAP_ZERO_MEMORY
    mov r8, rbx
    call HeapAlloc
    jmp done
    
alloc_failed:
    xor eax, eax
    
done:
    pop rbx
    ret
Heap_Alloc ENDP

; Heap_Free PROC
; RCX = pointer
Heap_Free PROC
    test rcx, rcx
    jz done
    
    mov rdx, rcx
    mov rcx, g_heap
    test rcx, rcx
    jz done
    
    xor r8d, r8d          ; dwFlags
    call HeapFree
    
done:
    ret
Heap_Free ENDP

END
```

## Testing the Patch

### Step 1: Build the patched version
```batch
cd d:\rawrxd\compilers\native_toolchain

; Assemble patch
ml64 /c sovereign_memory_patch.asm

; Link with Sovereign
link sovereign_main.obj sovereign_memory_patch.obj /out:sovereign_patched.exe
```

### Step 2: Test with heap diagnostic
```powershell
.\test_heap.exe
; Should show: 11/11 tests passed
```

### Step 3: Test model loading
```powershell
.\sovereign_patched.exe load "model.gguf"
; Should load without crash
```

### Step 4: Run full test suite
```powershell
powershell -ExecutionPolicy Bypass -File .\test_agentic_features.ps1 -ModelPath "model.gguf"
```

## Verification Checklist

- [ ] `test_heap.exe` passes all tests
- [ ] `sovereign_patched.exe` runs without crash
- [ ] Model loading succeeds
- [ ] Inference produces output
- [ ] No memory leaks (use Application Verifier)
- [ ] Performance is acceptable

## Rollback Plan

If the patch causes issues:

1. Keep original `sovereign.exe` as `sovereign_backup.exe`
2. Test patched version alongside original
3. If issues arise, restore backup
4. Investigate and refine patch

## Additional Notes

### Why Process Heap?
- Always available (no initialization needed)
- Thread-safe (serialized by default)
- Optimized by Windows
- No custom heap management bugs

### When to Use Custom Heap?
- Only if you need:
  - Low-fragmentation heap (LFH)
  - Separate heap for different components
  - Heap debugging features
  - NUMA-aware allocations

### Performance Considerations
- Process heap is slightly slower due to serialization
- For multi-threaded scenarios, consider:
  - Thread-local allocators
  - Memory pools for frequent allocations
  - Lock-free allocators

## References

- `test_heap.c` - Working heap implementation
- `test_heap.exe` - Verification tool
- `DIAGNOSTIC_TOOLS_SUMMARY.md` - Full diagnostic report
