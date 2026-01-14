; theme_manager_masm.asm
; Pure MASM x64 - Theme Manager (converted from C++ ThemeManager class)
; Manages IDE color schemes, transparency, and live theme switching

option casemap:none

extern masm_malloc : proc
extern masm_free : proc
EXTERN memcpy:PROC
EXTERN console_log:PROC

; ============================================================================
; CONSTANTS & ENUMERATIONS
; ============================================================================

; Theme ID constants
THEME_DARK EQU 0
THEME_LIGHT EQU 1
THEME_CUSTOM EQU 2

; Color component size
COLOR_SIZE EQU 4                   ; RGBA32

.data
    szThemeLoaded DB "[THEME] Theme loaded: %s (opacity=%.2f)", 0
    szThemeChanged DB "[THEME] Theme changed from %s to %s", 0
    szCustomTheme DB "[THEME] Custom theme applied", 0
    fOne REAL4 1.0
    szDarkThemeName DB "Dark", 0
    szLightThemeName DB "Light", 0

.code

; ============================================================================
; THEME_COLORS STRUCTURE (all colors + opacity settings)
; ============================================================================

; Editor colors (8 colors * 4 bytes = 32 bytes)
; Syntax colors (8 colors * 4 bytes = 32 bytes)
; Chat colors (7 colors * 4 bytes = 28 bytes)
; UI colors (14 colors * 4 bytes = 56 bytes)
; Opacity values (4 floats * 4 bytes = 16 bytes)
; Total: 164 bytes

; ============================================================================

; theme_create()
; Create theme colors structure with default dark theme
; Returns: RAX = pointer to THEME_COLORS (malloc'd)
PUBLIC theme_create
theme_create PROC
    mov rcx, 164                   ; Size of THEME_COLORS
    call masm_malloc
    
    ; Initialize with dark theme defaults
    ; This would fill in default color values
    ; For now, return the allocated structure
    
    ret
theme_create ENDP

; ============================================================================

; theme_set_dark(RCX = themeColors)
; Apply dark theme colors and settings
PUBLIC theme_set_dark
theme_set_dark PROC
    ; Set editor colors to dark palette
    ; editorBackground = 0x1E1E1E (dark gray)
    mov dword ptr [rcx], 0x1E1E1EFF
    
    ; editorForeground = 0xE0E0E0 (light gray)
    mov dword ptr [rcx + 4], 0xE0E0E0FF
    
    ; Set default opacities to 1.0
    movss xmm0, [fOne]
    mov [rcx + 160], eax           ; windowOpacity = 1.0 (using eax from movss)
    ; Wait, movss to eax is not direct. 
    ; Let's use a temporary register or just move from memory.
    mov eax, dword ptr [fOne]
    mov [rcx + 160], eax
    mov [rcx + 164], eax
    mov [rcx + 168], eax
    mov [rcx + 172], eax
    
    lea rcx, [szThemeLoaded]
    lea rdx, [szDarkThemeName]
    movss xmm2, [fOne]
    mov r8, qword ptr [fOne] ; For vararg
    call console_log
    
    ret
theme_set_dark ENDP

; ============================================================================

; theme_set_light(RCX = themeColors)
; Apply light theme colors and settings
PUBLIC theme_set_light
theme_set_light PROC
    ; Set editor colors to light palette
    ; editorBackground = 0xFFFFFF (white)
    mov dword ptr [rcx], 0xFFFFFFFF
    
    ; editorForeground = 0x1E1E1E (dark gray)
    mov dword ptr [rcx + 4], 0x1E1E1EFF
    
    ; Set default opacities
    mov eax, dword ptr [fOne]
    mov [rcx + 160], eax
    mov [rcx + 164], eax
    mov [rcx + 168], eax
    mov [rcx + 172], eax
    
    ret
theme_set_light ENDP

; ============================================================================

; theme_set_color(RCX = themeColors, RDX = colorIndex, R8d = colorValue)
; Set individual color value (RGBA32)
PUBLIC theme_set_color
theme_set_color PROC
    ; RCX = themeColors pointer
    ; RDX = index (0-36)
    ; R8d = RGBA color
    
    imul rdx, 4                    ; Convert index to byte offset
    mov [rcx + rdx], r8d           ; Store color
    
    ret
theme_set_color ENDP

; ============================================================================

; theme_set_opacity(RCX = themeColors, RDX = opacityType, XMM0 = value [0.0-1.0])
; Set opacity for specific UI element
; opacityType: 0=window, 1=dock, 2=chat, 3=editor
PUBLIC theme_set_opacity
theme_set_opacity PROC
    ; Calculate offset: 160 + (opacityType * 4)
    imul rdx, 4
    add rdx, 160
    
    movss [rcx + rdx], xmm0
    
    ret
theme_set_opacity ENDP

; ============================================================================

; theme_get_color(RCX = themeColors, RDX = colorIndex)
; Get individual color value
; Returns: EAX = RGBA color
PUBLIC theme_get_color
theme_get_color PROC
    imul rdx, 4
    mov eax, [rcx + rdx]
    ret
theme_get_color ENDP

; ============================================================================

; theme_destroy(RCX = themeColors)
; Free theme colors structure
PUBLIC theme_destroy
theme_destroy PROC
    call masm_free
    ret
theme_destroy ENDP

; ============================================================================

END





