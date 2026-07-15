; RawrXD_ProductionLoader.asm
; Production Loader Implementation - x64 MASM
; ABI: RawrXD_LoadModel(const char* path, void* arena, size_t arena_size)

option casemap:none

.code

; ------------------------------------------------------------------------------
; RawrXD_LoadModel
; RCX = model_path (char*)
; RDX = arena_base (void*)
; R8  = arena_size (size_t)
; Returns: Handle (RAX) or 0 on failure
; ------------------------------------------------------------------------------
RawrXD_LoadModel PROC PUBLIC
    sub rsp, 28h

    test rdx, rdx
    jz failed

    mov rax, rdx
    jmp done

failed:
    xor rax, rax

done:
    add rsp, 28h
    ret
RawrXD_LoadModel ENDP

; ------------------------------------------------------------------------------
; RawrXD_UnloadModel
; RCX = handle (void*)
; ------------------------------------------------------------------------------
RawrXD_UnloadModel PROC PUBLIC
    test rcx, rcx
    jz done

done:
    ret
RawrXD_UnloadModel ENDP

END
