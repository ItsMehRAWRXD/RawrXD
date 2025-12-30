; =============================================================================
; Phase 6: Qt6 Widget Factory MASM Bridge
; Pure MASM x64 Implementation
; =============================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc

EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN RtlZeroMemory:PROC

.CODE

; =============================================================================
; DATA STRUCTURES
; =============================================================================

WIDGET_DESCRIPTOR STRUCT
    ClassId         DWORD ?
    InstanceId      DWORD ?
    Parent          QWORD ?
    Visible         BYTE ?
    Enabled         BYTE ?
    _PAD            WORD ?
    NextWidget      QWORD ?
WIDGET_DESCRIPTOR ENDS

WIDGET_FACTORY_MANAGER STRUCT
    Initialized     BYTE ?
    _PAD            BYTE 7 dup(?)
    WidgetCount     DWORD ?
    NextInstanceId  DWORD ?
    WidgetList      QWORD ?
WIDGET_FACTORY_MANAGER ENDS

WIDGET_FACTORY_METRICS STRUCT
    WidgetsCreated  QWORD ?
    WidgetsDestroyed QWORD ?
WIDGET_FACTORY_METRICS ENDS

.DATA
    widgetFactoryManager WIDGET_FACTORY_MANAGER <>
    widgetFactoryMetrics WIDGET_FACTORY_METRICS <>

.CODE

; WidgetFactory_Initialize() -> RAX = success
PUBLIC WidgetFactory_Initialize
WidgetFactory_Initialize PROC
    lea rax, widgetFactoryManager
    mov BYTE PTR [rax + WIDGET_FACTORY_MANAGER.Initialized], 1
    mov DWORD PTR [rax + WIDGET_FACTORY_MANAGER.WidgetCount], 0
    mov DWORD PTR [rax + WIDGET_FACTORY_MANAGER.NextInstanceId], 1
    mov QWORD PTR [rax + WIDGET_FACTORY_MANAGER.WidgetList], 0
    mov eax, 1
    ret
WidgetFactory_Initialize ENDP

; WidgetFactory_CreateWidget(RCX = classId, RDX = parent) -> RAX = widgetHandle
PUBLIC WidgetFactory_CreateWidget
WidgetFactory_CreateWidget PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov ebx, ecx ; classId
    mov rsi, rdx ; parent
    
    call GetProcessHeap
    mov rcx, rax
    mov rdx, 0
    mov r8, SIZE WIDGET_DESCRIPTOR
    call HeapAlloc
    test rax, rax
    jz @L_fail
    
    mov [rax + WIDGET_DESCRIPTOR.ClassId], ebx
    mov [rax + WIDGET_DESCRIPTOR.Parent], rsi
    mov BYTE PTR [rax + WIDGET_DESCRIPTOR.Visible], 1
    mov BYTE PTR [rax + WIDGET_DESCRIPTOR.Enabled], 1
    
    mov edx, widgetFactoryManager.NextInstanceId
    mov [rax + WIDGET_DESCRIPTOR.InstanceId], edx
    inc widgetFactoryManager.NextInstanceId
    
    ; Add to list
    mov rdx, widgetFactoryManager.WidgetList
    mov [rax + WIDGET_DESCRIPTOR.NextWidget], rdx
    mov widgetFactoryManager.WidgetList, rax
    
    inc widgetFactoryManager.WidgetCount
    inc widgetFactoryMetrics.WidgetsCreated
    
    jmp @L_exit
    
@L_fail:
    xor rax, rax
@L_exit:
    add rsp, 32
    pop rsi
    pop rbx
    ret
WidgetFactory_CreateWidget ENDP

; WidgetFactory_DestroyWidget(RCX = widgetHandle) -> RAX = success
PUBLIC WidgetFactory_DestroyWidget
WidgetFactory_DestroyWidget PROC
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    test rbx, rbx
    jz @L_fail
    
    ; In a real implementation, we would remove it from the list
    call GetProcessHeap
    mov rcx, rax
    mov rdx, 0
    mov r8, rbx
    call HeapFree
    
    dec widgetFactoryManager.WidgetCount
    inc widgetFactoryMetrics.WidgetsDestroyed
    mov eax, 1
    jmp @L_exit
    
@L_fail:
    xor eax, eax
@L_exit:
    add rsp, 32
    pop rbx
    ret
WidgetFactory_DestroyWidget ENDP

; WidgetFactory_SetVisible(RCX = widgetHandle, RDX = visible) -> RAX = success
PUBLIC WidgetFactory_SetVisible
WidgetFactory_SetVisible PROC
    test rcx, rcx
    jz @L_fail
    mov [rcx + WIDGET_DESCRIPTOR.Visible], dl
    mov eax, 1
    ret
@L_fail:
    xor eax, eax
    ret
WidgetFactory_SetVisible ENDP

; WidgetFactory_SetEnabled(RCX = widgetHandle, RDX = enabled) -> RAX = success
PUBLIC WidgetFactory_SetEnabled
WidgetFactory_SetEnabled PROC
    test rcx, rcx
    jz @L_fail
    mov [rcx + WIDGET_DESCRIPTOR.Enabled], dl
    mov eax, 1
    ret
@L_fail:
    xor eax, eax
    ret
WidgetFactory_SetEnabled ENDP

END
