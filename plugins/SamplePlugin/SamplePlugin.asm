; ============================================================================
; SamplePlugin.asm - Example RawrXD Plugin in MASM x64
; ============================================================================
; This is a minimal working example of a RawrXD plugin written in pure
; x64 assembly language. It demonstrates:
;   - Plugin initialization and shutdown
;   - Calling IDE services via function pointers
;   - Registering commands
;   - Handling events
;
; BUILD:
;   ml64.exe /c /W3 /nologo SamplePlugin.asm
;   link.exe /DLL /OUT:SamplePlugin.dll SamplePlugin.obj /SUBSYSTEM:WINDOWS
;
; INSTALL:
;   Copy SamplePlugin.dll to RawrXD/plugins/
; ============================================================================

; External Windows API functions
extern GetModuleHandleA:proc
extern GetProcAddress:proc
extern MessageBoxA:proc
extern lstrcpyA:proc
extern lstrcatA:proc
extern wsprintfA:proc

; Export our plugin entry points
public RawrXD_PluginInitialize
public RawrXD_PluginShutdown

; ============================================================================
; Data Section
; ============================================================================
.data

; Plugin metadata
PluginName          db "SampleMASMPlugin", 0
PluginVersion       db "1.0.0", 0
PluginDescription   db "A sample plugin written in x64 assembly", 0

; Command IDs
CommandHelloId      db "sample.hello", 0
CommandHelloName    db "Hello from MASM", 0
CommandHelloKeybind db "Ctrl+Shift+H", 0

; UI strings
HelloMessage        db "Hello from RawrXD MASM Plugin!", 0
DialogTitle         db "MASM Plugin", 0
InitMessage         db "MASM Plugin initialized successfully!", 0
ShutdownMessage     db "MASM Plugin shutting down...", 0
EventMessage        db "Event received: ", 0

; Buffer for dynamic strings
Buffer              db 256 dup(0)

; Plugin context (our state)
PluginContext       struct
    api             qword ?     ; Pointer to RawrXD_API
    command_handle  qword ?     ; Handle to registered command
    event_hook_id   dword ?     ; Event hook identifier
PluginContext       ends

; Global context instance
align 8
g_Context           PluginContext <>

; ============================================================================
; Code Section
; ============================================================================
.code

; ============================================================================
; RawrXD_PluginInitialize - Plugin Entry Point (REQUIRED EXPORT)
; ============================================================================
; Parameters:
;   RCX = RawrXD_API* api (function pointer table)
;   RDX = uint32_t api_version
;   R8  = void** plugin_context (OUT: store our context here)
; Returns:
;   RAX = 0 on success, non-zero on failure
; ============================================================================
RawrXD_PluginInitialize proc export frame
    ; Save non-volatile registers
    push rbx
    push rdi
    push rsi
    .pushreg rbx
    .pushreg rdi
    .pushreg rsi
    .endprolog
    
    ; Store API pointer in our context
    mov [g_Context.api], rcx
    
    ; Check API version (major version in upper 16 bits)
    mov eax, edx
    shr eax, 16
    cmp eax, 1              ; Require major version 1
    jne version_mismatch
    
    ; Log initialization
    mov rbx, rcx            ; RBX = API pointer
    
    ; Call api->Log(RAWRXD_LOG_INFO, PluginName, "Initializing...")
    mov rcx, 1              ; RAWRXD_LOG_INFO
    lea rdx, PluginName
    lea r8, InitMessage
    call qword ptr [rbx]    ; api->Log is first field after api_version
    
    ; Register a command: api->RegisterCommand(...)
    ; Parameters: command_id, display_name, keybinding, callback, context
    lea rcx, CommandHelloId
    lea rdx, CommandHelloName
    lea r8, CommandHelloKeybind
    lea r9, CommandHelloCallback
    mov r10, [g_Context.api]
    
    ; Save parameters for stack
    sub rsp, 40             ; Shadow space + alignment
    mov [rsp+32], r9        ; callback
    mov r9, r8              ; keybinding
    mov r8, rdx             ; display_name
    mov rdx, rcx            ; command_id
    mov rcx, r10            ; api pointer (not used directly, function is in table)
    
    ; Call RegisterCommand via function pointer
    mov rax, [g_Context.api]
    add rax, 64             ; Offset to RegisterCommand in API struct
    call qword ptr [rax]
    
    ; Store command handle
    mov [g_Context.command_handle], rax
    
    add rsp, 40             ; Clean up stack
    
    ; Store context pointer for IDE
    mov rax, [g_Context.api]
    mov [r8], rax           ; *plugin_context = our context
    
    ; Show success message box
    xor r9d, r9d            ; MB_OK
    lea r8, DialogTitle
    lea rdx, InitMessage
    xor ecx, ecx            ; HWND = NULL (desktop)
    call MessageBoxA
    
    ; Return success
    xor eax, eax
    jmp init_done
    
version_mismatch:
    ; Log version mismatch
    mov eax, 1              ; Return error code 1
    
init_done:
    ; Restore registers
    pop rsi
    pop rdi
    pop rbx
    ret
RawrXD_PluginInitialize endp

; ============================================================================
; RawrXD_PluginShutdown - Plugin Cleanup (OPTIONAL EXPORT)
; ============================================================================
; Parameters:
;   RCX = void* plugin_context
; Returns:
;   RAX = 0 on success
; ============================================================================
RawrXD_PluginShutdown proc export frame
    .endprolog
    
    ; Log shutdown
    mov rbx, [g_Context.api]
    test rbx, rbx
    jz shutdown_done        ; Skip if no API
    
    ; Call api->Log(RAWRXD_LOG_INFO, PluginName, "Shutting down...")
    mov rcx, 1              ; RAWRXD_LOG_INFO
    lea rdx, PluginName
    lea r8, ShutdownMessage
    call qword ptr [rbx]
    
    ; Unregister our command if we have one
    mov rax, [g_Context.command_handle]
    test rax, rax
    jz no_command
    
    ; Call api->UnregisterCommand(handle)
    mov rcx, rax
    mov rax, [g_Context.api]
    add rax, 72             ; Offset to UnregisterCommand
    call qword ptr [rax]
    
no_command:
    ; Show shutdown message
    xor r9d, r9d
    lea r8, DialogTitle
    lea rdx, ShutdownMessage
    xor ecx, ecx
    call MessageBoxA
    
shutdown_done:
    xor eax, eax            ; Return success
    ret
RawrXD_PluginShutdown endp

; ============================================================================
; CommandHelloCallback - Command Handler
; ============================================================================
; Parameters:
;   RCX = void* plugin_context
;   RDX = const char* args
;   R8  = char* output_buffer
;   R9  = size_t output_buffer_size
; Returns:
;   RAX = 0 on success
; ============================================================================
CommandHelloCallback proc frame
    push rbx
    .pushreg rbx
    .endprolog
    
    mov rbx, rcx            ; Save context
    
    ; Show hello message box
    xor r9d, r9d            ; MB_OK
    lea r8, DialogTitle
    lea rdx, HelloMessage
    xor ecx, ecx
    call MessageBoxA
    
    ; Write response to output buffer
    ; strncpy(output_buffer, "Hello from MASM!", output_buffer_size)
    mov rcx, r8             ; output_buffer
    lea rdx, HelloMessage
    mov r8, r9              ; output_buffer_size
    call lstrcpyA
    
    ; Return success
    xor eax, eax
    pop rbx
    ret
CommandHelloCallback endp

; ============================================================================
; EventHandler - Example Event Handler
; ============================================================================
; Parameters:
;   RCX = void* plugin_context
;   RDX = const char* event_name
;   R8  = const char* event_data
;   R9  = RawrXD_DocumentHandle document
; Returns:
;   RAX = 0 if handled, 1 to continue
; ============================================================================
EventHandler proc frame
    push rbx
    push rdi
    push rsi
    .pushreg rbx
    .pushreg rdi
    .pushreg rsi
    .endprolog
    
    mov rbx, rcx            ; plugin_context
    mov rdi, rdx            ; event_name
    mov rsi, r8             ; event_data
    
    ; Build message: "Event received: " + event_name
    lea rcx, Buffer
    lea rdx, EventMessage
    call lstrcpyA
    
    lea rcx, Buffer
    mov rdx, rdi
    call lstrcatA
    
    ; Log the event
    mov rax, [g_Context.api]
    test rax, rax
    jz event_done
    
    mov rcx, 0              ; RAWRXD_LOG_DEBUG
    lea rdx, PluginName
    lea r8, Buffer
    call qword ptr [rax]
    
event_done:
    mov eax, 1              ; Return 1 to continue processing (don't block)
    pop rsi
    pop rdi
    pop rbx
    ret
EventHandler endp

; ============================================================================
; DLL Entry Point (required for Windows DLLs)
; ============================================================================
DllMain proc frame
    .endprolog
    
    ; We don't need to do anything special on DLL attach/detach
    ; The plugin lifecycle is managed via RawrXD_PluginInitialize/Shutdown
    
    mov eax, 1              ; Return TRUE (success)
    ret
DllMain endp

; ============================================================================
; End of file
; ============================================================================
end
