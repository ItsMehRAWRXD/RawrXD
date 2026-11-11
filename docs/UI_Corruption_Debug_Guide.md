# RawrXD IDE UI Corruption Debug Guide

## Problem Summary

The sidebar UI is displaying corrupted text:
- "New Folder" → "lew Folde" (off by +1 byte)
- "Install Extension" → "nstal" or "ninsta" (truncated/misaligned)

## Root Cause

**Structure padding/alignment mismatch** between C++ and ASM code.

### The Bug

When you have a structure like:

```cpp
struct CommandEntry {
    uint32_t    commandId;      // 4 bytes
    const char* namePtr;        // 8 bytes (needs 8-byte alignment!)
    // ...
};
```

The compiler inserts **4 bytes of padding** after `commandId` to align `namePtr` on an 8-byte boundary.

**Total size = 40 bytes, not 36!**

### How the Corruption Happens

If your ASM code uses the wrong stride:

```asm
; WRONG - assumes no padding
mov rcx, 36                 ; sizeof(CommandEntry) - WRONG!
mul rcx
mov rdi, [rsi+rax+4]       ; offset 4 for namePtr - WRONG!
; Result: Points to middle of padding or wrong entry entirely
```

With the correct stride:

```asm
; CORRECT - accounts for padding
mov rcx, 40                 ; sizeof(CommandEntry) - CORRECT!
mul rcx
mov rdi, [rsi+rax+8]       ; offset 8 for namePtr - CORRECT!
```

## Visual Explanation

Memory layout with the bug:

```
Entry 0 @ 0x1000:
  [00-03] commandId:    01 00 00 00     (ID = 1)
  [04-07] padding:      00 00 00 00     (padding bytes)
  [08-0F] namePtr:      00 20 00 00 00 00 00 00  (ptr = 0x2000)
  ...

Entry 1 @ 0x1028 (0x1000 + 40):
  [28-2B] commandId:    02 00 00 00     (ID = 2)
  ...

String at 0x2000: "New Folder\0"
  [00] 'N' (0x4E)
  [01] 'e' (0x65)
  [02] 'w' (0x77)
  ...
```

If you read at offset 4 instead of 8:
- You get the padding bytes (0x00000000) as a pointer → CRASH or garbage
- Or if you read at offset 5: you get 0x0000000000002000 + misalignment

If you read string at offset 9 instead of 8:
- Points to 'e' instead of 'N' → "ew Folder"

## Debugging Steps

### 1. Verify Structure Size in C++

Add this to your code:

```cpp
#include <type_traits>

static_assert(sizeof(CommandEntry) == 40, "Wrong size!");
static_assert(alignof(CommandEntry) == 8, "Wrong alignment!");
static_assert(offsetof(CommandEntry, namePtr) == 8, "Wrong namePtr offset!");
```

### 2. Memory Dump in Debugger

Set a breakpoint before your render loop and check:

```cpp
CommandEntry* entry = &m_commandRegistry[0];
// In debugger, examine:
// &entry->commandId    should be +0
// &entry->namePtr      should be +8
// sizeof(*entry)       should be 40
```

### 3. ASM Verification

In your MASM code, add debug output:

```asm
; Before using the pointer
mov rax, rbx                ; index
mov rcx, 40
mul rcx                     ; rax = offset from base
mov rdi, rsi                ; base
add rdi, rax                ; entry address

; Debug: Output the calculated address
lea rcx, debugFmt
mov rdx, rbx                ; index
mov r8, rdi               ; entry address
mov r9, [rdi+8]           ; namePtr value
push qword ptr [r9]       ; first 8 bytes of string
sub rsp, 32
call wsprintfA
add rsp, 40
call OutputDebugStringA
```

### 4. Check for Off-by-One

If you see:
- "lew Folde" → your pointer is +1 (reading 'e' instead of 'N')
- "ew Folder" → your pointer is +1
- "w Folder" → your pointer is +2
- " Folder" → your pointer is +3

## The Fix

### Option 1: Use Explicit Padding (Recommended)

**C++:**
```cpp
struct alignas(8) CommandEntry {
    uint32_t    commandId;
    uint32_t    _padding;        // Explicit padding
    const char* namePtr;         // Now at offset 8
    // ...
};
```

**ASM:**
```asm
CommandEntry STRUCT ALIGN(8)
    commandId   DWORD ?
    _padding    DWORD ?          ; Explicit
    namePtr     QWORD ?          ; Offset 8
    ; ...
CommandEntry ENDS
```

### Option 2: Pack the Structure

**C++:**
```cpp
#pragma pack(push, 4)
struct CommandEntry {
    uint32_t    commandId;
    const char* namePtr;         // At offset 4, misaligned!
    // ...
};
#pragma pack(pop)
```

**Warning:** Misaligned pointers can hurt performance or crash on some architectures.

### Option 3: Use Array Indexing Instead of Pointer Math

**ASM:**
```asm
; Instead of: mov rax, [rsi+rbx*40+8]
; Use:        mov rax, [rsi+rbx*8+8]  ; scale factor

; Actually, for x64:
mov rax, rbx
imul rax, 40                ; rax = index * sizeof(entry)
mov rdi, [rsi+rax+8]        ; rdi = entry->namePtr
```

## Testing the Fix

1. **Build with debug output enabled**
2. **Run with debugger attached**
3. **Set breakpoint at DrawTextA call**
4. **Verify R8 (string pointer) points to correct string:**
   - Should point to 'N' for "New Folder"
   - Should NOT point to 'e', 'w', or ' '
5. **Check memory at pointer:**
   - Should see: `4E 65 77 20 46 6F 6C 64 65 72 00`
   - Not: `65 77 20 46 6F 6C 64 65 72 00 ??`

## Prevention

1. **Always use `sizeof` in C++ and verify in ASM:**
   ```cpp
   constexpr uint32_t ENTRY_SIZE = sizeof(CommandEntry);
   ```
   ```asm
   mov rcx, ENTRY_SIZE    ; Use equate, not hardcoded value
   ```

2. **Add static assertions for structure layout:**
   ```cpp
   static_assert(offsetof(CommandEntry, namePtr) == 8);
   ```

3. **Use packed structures only when necessary:**
   - Prefer explicit padding for clarity
   - Document alignment requirements

4. **Validate pointers before use:**
   ```asm
   test rcx, rcx
   jz error_handler
   
   mov al, [rcx]          ; Check first byte
   cmp al, 20h
   jb error_handler       ; < space = probably wrong
   ```

## References

- `d:\RawrXD\asm\CommandRegistry_Fix.asm` - Fixed ASM implementation
- `d:\RawrXD\src\ide\CommandRegistry.h` - C++ header with validation
- Microsoft x64 Calling Convention: https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
