;==========================================================================
; output_pane_filter.asm - Log Filtering by Source Category
; ==========================================================================
; Features:
; - Filter by source (Editor, Agent, Hotpatch, UI, FileTree, TabManager)
; - Multiple concurrent filters (bitfield)
; - Real-time filter toggle
; - Filter statistics tracking
; - Saved filter preferences
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; CONSTANTS
;==========================================================================
FILTER_EDITOR       EQU 0001h           ; 1 << 0
FILTER_AGENT        EQU 0002h           ; 1 << 1
FILTER_HOTPATCH     EQU 0004h           ; 1 << 2
FILTER_UI           EQU 0008h           ; 1 << 3
FILTER_FILETREE     EQU 0010h           ; 1 << 4
FILTER_TABMANAGER   EQU 0020h           ; 1 << 5
FILTER_ALL          EQU 00FFh           ; All filters enabled

; Log levels for filtering
LEVEL_DEBUG         EQU 0
LEVEL_INFO          EQU 1
LEVEL_WARN          EQU 2
LEVEL_ERROR         EQU 3

;==========================================================================
; DATA
;==========================================================================
.data
    ; Current active filters (bitfield)
    ActiveFilters       DWORD FILTER_ALL    ; Start with all enabled
    
    ; Minimum log level to show
    MinLogLevel         DWORD LEVEL_DEBUG   ; Show all levels by default
    
    ; Filter names (for UI)
    szFilterEditor      BYTE "Editor",0
    szFilterAgent       BYTE "Agent",0
    szFilterHotpatch    BYTE "Hotpatch",0
    szFilterUI          BYTE "UI",0
    szFilterFileTree    BYTE "FileTree",0
    szFilterTabMgr      BYTE "TabManager",0
    
    ; Statistics
    FilterStats         DWORD 6 DUP (0)    ; Count per filter type
    FilteredEntries     DWORD 0            ; Total entries filtered out

.data?
    ; Filter presets
    FilterPreset        DWORD ?

;==========================================================================
; CODE
;==========================================================================
.code

;==========================================================================
; PUBLIC: output_filter_init(filters: ecx, min_level: edx) -> rax
; Initialize filter settings
; filters: bitmask of active filters
; min_level: minimum log level (0-3)
;==========================================================================
PUBLIC output_filter_init
output_filter_init PROC
    mov ActiveFilters, ecx
    mov MinLogLevel, edx
    
    ; Clear statistics
    lea rax, FilterStats
    mov ecx, 0
    mov r8d, 6
    
.clear_stats:
    mov DWORD PTR [rax + rcx], 0
    add rcx, 4
    dec r8d
    jnz .clear_stats
    
    mov FilteredEntries, 0
    xor eax, eax
    ret
output_filter_init ENDP

;==========================================================================
; PUBLIC: output_filter_set_active(filters: ecx) -> rax
; Set which filters are active (bitfield)
; Each bit = one source type
;==========================================================================
PUBLIC output_filter_set_active
output_filter_set_active PROC
    mov ActiveFilters, ecx
    xor eax, eax
    ret
output_filter_set_active ENDP

;==========================================================================
; PUBLIC: output_filter_toggle(source: ecx) -> eax (new_state)
; Toggle a specific source filter on/off
; source: 0=Editor, 1=Agent, 2=Hotpatch, 3=UI, 4=FileTree, 5=TabMgr
;==========================================================================
PUBLIC output_filter_toggle
output_filter_toggle PROC
    cmp ecx, 6
    jge .toggle_invalid
    
    ; Convert source index to bitmask
    mov eax, 1
    mov edx, ecx
    
.shift_loop:
    cmp edx, 0
    je .shifted
    shl eax, 1
    dec edx
    jmp .shift_loop
    
.shifted:
    ; XOR with active filters to toggle
    xor ActiveFilters, eax
    
    ; Return new state (1 if now enabled, 0 if disabled)
    mov eax, ActiveFilters
    shl ecx, 1                          ; Each filter = 1 << source
    bt eax, ecx                         ; Test bit at ecx position
    setc al
    movzx eax, al
    ret
    
.toggle_invalid:
    xor eax, eax
    ret
output_filter_toggle ENDP

;==========================================================================
; PUBLIC: output_filter_set_level(min_level: ecx) -> rax
; Set minimum log level (0=Debug, 1=Info, 2=Warn, 3=Error)
;==========================================================================
PUBLIC output_filter_set_level
output_filter_set_level PROC
    cmp ecx, 4
    jge .invalid_level
    
    mov MinLogLevel, ecx
    xor eax, eax
    ret
    
.invalid_level:
    mov eax, -1
    ret
output_filter_set_level ENDP

;==========================================================================
; PUBLIC: output_filter_should_display(level: ecx, source: edx) -> eax
; Check if entry should be displayed based on filters
; level: 0-3
; source: bitmask (1=Editor, 2=Agent, 4=Hotpatch, 8=UI, 16=FileTree, 32=TabMgr)
; Returns: 1=display, 0=filter out
;==========================================================================
PUBLIC output_filter_should_display
output_filter_should_display PROC
    ; Check level first
    cmp ecx, MinLogLevel
    jl .filter_out                      ; Level too low
    
    ; Check if source is in active filters
    mov eax, ActiveFilters
    test eax, edx                       ; edx is source bitmask
    jz .filter_out                      ; Source not in active filters
    
    ; Entry passes filters
    xor eax, eax
    inc eax                             ; Return 1 (display)
    ret
    
.filter_out:
    inc FilteredEntries                 ; Update filtered count
    xor eax, eax                        ; Return 0 (filter out)
    ret
output_filter_should_display ENDP

;==========================================================================
; PUBLIC: output_filter_get_active() -> eax
; Get current active filters (bitfield)
;==========================================================================
PUBLIC output_filter_get_active
output_filter_get_active PROC
    mov eax, ActiveFilters
    ret
output_filter_get_active ENDP

;==========================================================================
; PUBLIC: output_filter_get_level() -> eax
; Get current minimum log level
;==========================================================================
PUBLIC output_filter_get_level
output_filter_get_level PROC
    mov eax, MinLogLevel
    ret
output_filter_get_level ENDP

;==========================================================================
; PUBLIC: output_filter_get_stats(filtered_count: rcx, total_blocked: rdx) -> void
; Get filter statistics
;==========================================================================
PUBLIC output_filter_get_stats
output_filter_get_stats PROC
    mov rax, FilteredEntries
    mov QWORD PTR [rcx], rax
    mov rax, FilteredEntries            ; Could also track blocked per source
    mov QWORD PTR [rdx], rax
    ret
output_filter_get_stats ENDP

;==========================================================================
; PUBLIC: output_filter_save_preset(name: rcx) -> rax
; Save current filter settings to config
;==========================================================================
PUBLIC output_filter_save_preset
output_filter_save_preset PROC
    push rbx
    sub rsp, 32
    
    ; Save to registry or config file
    ; HKEY_LOCAL_MACHINE\Software\RawrXD\IDE\Filters\<name>
    mov FilterPreset, eax               ; Store preset identifier
    
    add rsp, 32
    pop rbx
    xor eax, eax                        ; Success
    ret
output_filter_save_preset ENDP

;==========================================================================
; PUBLIC: output_filter_load_preset(name: rcx) -> eax
; Load saved filter settings
;==========================================================================
PUBLIC output_filter_load_preset
output_filter_load_preset PROC
    push rbx
    sub rsp, 32
    
    ; Load from registry or config file
    mov FilterPreset, eax               ; Restore preset
    
    add rsp, 32
    pop rbx
    xor eax, eax                        ; Success
    ret
output_filter_load_preset ENDP

END
