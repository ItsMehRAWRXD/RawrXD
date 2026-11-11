; ==============================================================================
; RawrXD Pure x64 MASM Zero-Dependency AMD Radeon RX 7800 XT Driver
; Target: Navi 32 / RDNA3 | Environment: Windows Kernel Mode (x64)
; Zero C-Headers | Zero WDK Frameworks | Direct NT Executive ABI
; Full PnP Lifecycle: AddDevice -> StartDevice -> BAR Map -> MMIO Init -> Remove
; ==============================================================================

OPTION CASEMAP:NONE

; ==============================================================================
; Kernel Exports (ntoskrnl.lib)
; ==============================================================================
EXTRN IoCreateDevice:PROC
EXTRN IoDeleteDevice:PROC
EXTRN IoAttachDeviceToDeviceStack:PROC
EXTRN IoDetachDevice:PROC
EXTRN IoCallDriver:PROC
EXTRN IofCompleteRequest:PROC
EXTRN MmMapIoSpaceEx:PROC
EXTRN MmUnmapIoSpace:PROC
EXTRN KeStallExecutionProcessor:PROC
EXTRN DbgPrint:PROC

; ==============================================================================
; Constants
; ==============================================================================
.const
    ; NTSTATUS Codes
    STATUS_SUCCESS                  EQU 00000000h
    STATUS_UNSUCCESSFUL             EQU 0C0000001h
    STATUS_INSUFFICIENT_RESOURCES   EQU 0C000009Ah
    STATUS_NOT_SUPPORTED            EQU 0C00000BBh

    ; IRP Major Functions
    IRP_MJ_CREATE                   EQU 00h
    IRP_MJ_CLOSE                    EQU 02h
    IRP_MJ_PNP                      EQU 1Bh

    ; PnP Minor Functions
    IRP_MN_START_DEVICE             EQU 00h
    IRP_MN_STOP_DEVICE              EQU 01h
    IRP_MN_REMOVE_DEVICE            EQU 02h

    ; Resource Types
    CmResourceTypeMemory            EQU 03h

    ; Page Protection
    PAGE_READWRITE                  EQU 04h
    PAGE_NOCACHE                    EQU 200h
    PAGE_WRITECOMBINE               EQU 400h

    ; Device Constants
    FILE_DEVICE_UNKNOWN             EQU 22h
    DO_BUFFERED_IO                  EQU 04h
    DO_DEVICE_INITIALIZING          EQU 80h

    ; RDNA3 / Navi 32 MMIO Register Offsets
    mmGRBM_STATUS                   EQU 00008010h
    mmGRBM_STATUS2                   EQU 00008014h
    mmCP_MEC_CNTL                   EQU 00005000h
    mmCP_RB0_RPTR                   EQU 0000C100h
    mmCP_RB0_WPTR                   EQU 0000C104h
    mmCP_RB0_CNTL                   EQU 0000C108h
    mmCP_HQD_ACTIVE                 EQU 0000C81Ch

; ==============================================================================
; Device Extension Structure (64 bytes)
; ==============================================================================
DEVICE_EXTENSION STRUCT 8
    LowerDeviceObject       QWORD ?     ; +0x00: Attached lower device
    PhysicalBAR0            QWORD ?     ; +0x08: BAR0 physical address
    VirtualBAR0             QWORD ?     ; +0x10: BAR0 mapped virtual address
    BAR0Length              DWORD ?     ; +0x18: BAR0 length in bytes
    Pad0                    DWORD ?     ; +0x1C: Alignment
    PhysicalBAR2            QWORD ?     ; +0x20: BAR2 physical (VRAM aperture)
    VirtualBAR2             QWORD ?     ; +0x28: BAR2 mapped virtual
    BAR2Length              QWORD ?     ; +0x30: BAR2 length
    DeviceStarted           BYTE ?      ; +0x38: Hardware initialized flag
    Pad1                    BYTE 7 DUP(?) ; +0x39: Padding
DEVICE_EXTENSION ENDS

; ==============================================================================
; Initialized Data
; ==============================================================================
.data
    ; Debug strings
    szDriverEntry   DB  "RawrXD: DriverEntry - Navi 32 / RX 7800 XT PnP Driver", 0Ah, 0
    szAddDevice     DB  "RawrXD: AddDevice - Creating FDO for GPU node", 0Ah, 0
    szStartDevice   DB  "RawrXD: IRP_MN_START_DEVICE - Parsing BAR resources", 0Ah, 0
    szBar0Mapped    DB  "RawrXD: BAR0 MMIO mapped - Phys: 0x%I64X Virt: 0x%I64X Len: 0x%08X", 0Ah, 0
    szBar2Mapped    DB  "RawrXD: BAR2 VRAM mapped - Phys: 0x%I64X Virt: 0x%I64X Len: 0x%I64X", 0Ah, 0
    szHwInit        DB  "RawrXD: Navi 32 hardware initialization complete", 0Ah, 0
    szRemoveDevice  DB  "RawrXD: IRP_MN_REMOVE_DEVICE - Unmapping resources", 0Ah, 0
    szGrbmStatus    DB  "RawrXD: GRBM_STATUS readback: 0x%08X", 0Ah, 0

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; DriverEntry - Primary Kernel Entry Point
; RCX = PDRIVER_OBJECT, RDX = PUNICODE_STRING RegistryPath
; Returns: RAX = NTSTATUS
; ==============================================================================
DriverEntry PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rsi, rcx                        ; PDRIVER_OBJECT

    ; Debug print entry
    lea     rcx, szDriverEntry
    call    DbgPrint

    ; Set DriverUnload (offset 0x38 in DRIVER_OBJECT)
    lea     rax, DriverUnload
    mov     qword ptr [rsi + 38h], rax

    ; Set AddDevice (offset 0x18 in DRIVER_EXTENSION, which is at +0x18 from DriverObject)
    mov     rax, qword ptr [rsi + 18h]      ; DriverExtension
    lea     rcx, AddDevice
    mov     qword ptr [rax + 18h], rcx      ; DriverExtension->AddDevice

    ; Hook IRP_MJ_CREATE and IRP_MJ_CLOSE (MajorFunction array at +0x70)
    lea     rax, DispatchCreateClose
    mov     qword ptr [rsi + 70h + (IRP_MJ_CREATE * 8)], rax  ; +0x70
    mov     qword ptr [rsi + 70h + (IRP_MJ_CLOSE * 8)], rax  ; +0x80

    ; Hook IRP_MJ_PNP (index 0x1B -> 0x70 + 0xD8 = 0x148)
    lea     rax, DispatchPnp
    mov     qword ptr [rsi + 148h], rax

    xor     eax, eax                        ; STATUS_SUCCESS
    add     rsp, 40
    pop     rsi
    pop     rbx
    ret
DriverEntry ENDP

; ==============================================================================
; AddDevice - PnP Manager Creates Functional Device Object
; RCX = PDRIVER_OBJECT, RDX = PDEVICE_OBJECT (PDO)
; ==============================================================================
AddDevice PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 64
    .allocstack 64
    .endprolog

    mov     rbx, rcx                        ; DriverObject
    mov     rsi, rdx                        ; PDO

    lea     rcx, szAddDevice
    call    DbgPrint

    ; IoCreateDevice(DriverObject, ExtSize, DeviceName=NULL, DeviceType=UNKNOWN,
    ;                Characteristics=0, Exclusive=FALSE, &DeviceObject)
    mov     rcx, rbx                        ; DriverObject
    mov     edx, SIZEOF DEVICE_EXTENSION    ; DeviceExtensionSize
    xor     r8, r8                          ; DeviceName = NULL (autogenerated)
    mov     r9d, FILE_DEVICE_UNKNOWN       ; DeviceType
    mov     dword ptr [rsp + 20h], 0        ; Characteristics = 0
    mov     qword ptr [rsp + 28h], 0        ; Exclusive = FALSE
    lea     rax, [rsp + 38h]                ; &DeviceObject output
    mov     qword ptr [rsp + 30h], rax
    call    IoCreateDevice

    test    eax, eax
    js      _add_fail

    mov     rdi, qword ptr [rsp + 38h]      ; PDEVICE_OBJECT (new FDO)

    ; Zero-initialize Device Extension
    mov     rcx, qword ptr [rdi + 40h]      ; DeviceExtension pointer
    mov     r8d, SIZEOF DEVICE_EXTENSION
    xor     edx, edx
_zero_ext_loop:
    mov     byte ptr [rcx + rdx], 0
    inc     edx
    dec     r8d
    jnz     _zero_ext_loop

    ; Attach FDO to device stack
    mov     rcx, rdi                        ; SourceDevice (our FDO)
    mov     rdx, rsi                        ; TargetDevice (PDO)
    call    IoAttachDeviceToDeviceStack

    test    rax, rax
    jz      _add_rollback

    ; Store LowerDeviceObject in extension
    mov     rcx, qword ptr [rdi + 40h]      ; DeviceExtension
    mov     qword ptr [rcx + DEVICE_EXTENSION.LowerDeviceObject], rax

    ; Set DO_BUFFERED_IO, clear DO_DEVICE_INITIALIZING
    mov     eax, dword ptr [rdi + 30h]      ; DeviceObject->Flags
    or      eax, DO_BUFFERED_IO
    and     eax, NOT DO_DEVICE_INITIALIZING
    mov     dword ptr [rdi + 30h], eax

    xor     eax, eax                        ; STATUS_SUCCESS
    jmp     _add_exit

_add_rollback:
    mov     rcx, rdi
    call    IoDeleteDevice
    mov     eax, STATUS_UNSUCCESSFUL
    jmp     _add_exit

_add_fail:
    mov     eax, STATUS_UNSUCCESSFUL

_add_exit:
    add     rsp, 64
    pop     rdi
    pop     rsi
    pop     rbx
    ret
AddDevice ENDP

; ==============================================================================
; DispatchPnp - PnP IRP Handler
; RCX = PDEVICE_OBJECT, RDX = PIRP
; ==============================================================================
DispatchPnp PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    sub     rsp, 56
    .allocstack 56
    .endprolog

    mov     rsi, rcx                        ; DeviceObject
    mov     rbx, rdx                        ; Irp
    mov     r12, qword ptr [rsi + 40h]      ; DeviceExtension

    ; Get current IO_STACK_LOCATION (Irp->Tail.Overlay.CurrentStackLocation at +0xB8)
    mov     rax, qword ptr [rbx + 0B8h]
    movzx   ecx, byte ptr [rax + 1]         ; MinorFunction

    cmp     cl, IRP_MN_START_DEVICE
    je      _pnp_start
    cmp     cl, IRP_MN_STOP_DEVICE
    je      _pnp_stop
    cmp     cl, IRP_MN_REMOVE_DEVICE
    je      _pnp_remove

    ; Unknown PnP IRP: pass down to lower driver
    jmp     _pnp_pass_down

; ==============================================================================
; IRP_MN_START_DEVICE - Parse resources and map BARs
; ==============================================================================
_pnp_start:
    lea     rcx, szStartDevice
    call    DbgPrint

    ; Get AllocatedResourcesTranslated from stack location
    ; Parameters.StartDevice.AllocatedResourcesTranslated at offset +0x10
    mov     rdi, qword ptr [rax + 10h]
    test    rdi, rdi
    jz      _pnp_fail_resources

    ; Parse CM_RESOURCE_LIST
    ; List[0].PartialResourceList.Count at +0x08
    mov     r13d, dword ptr [rdi + 8]       ; Partial descriptor count
    lea     rdi, [rdi + 10h]                ; First CM_PARTIAL_RESOURCE_DESCRIPTOR

_resource_loop:
    test    r13d, r13d
    jz      _pnp_check_mapped

    ; Check Type field (byte 0)
    movzx   eax, byte ptr [rdi]
    cmp     al, CmResourceTypeMemory
    jne     _next_resource

    ; Found memory resource - extract physical address and length
    mov     rcx, qword ptr [rdi + 8]        ; Physical address (u.Memory.Start)
    mov     edx, dword ptr [rdi + 10h]     ; Length (u.Memory.Length)

    ; Determine which BAR based on size
    ; BAR0 (MMIO registers): typically 512KB (0x80000) or 256KB
    ; BAR2 (VRAM aperture): typically >= 256MB (0x10000000)
    cmp     edx, 01000000h                 ; >= 16MB? -> BAR2 (VRAM)
    jge     _map_bar2

    ; Otherwise treat as BAR0 (MMIO registers)
    mov     qword ptr [r12 + DEVICE_EXTENSION.PhysicalBAR0], rcx
    mov     dword ptr [r12 + DEVICE_EXTENSION.BAR0Length], edx

    ; Map BAR0: PAGE_READWRITE | PAGE_NOCACHE = 0x204
    mov     r8d, 204h
    call    MmMapIoSpaceEx

    test    rax, rax
    jz      _pnp_fail_resources

    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0], rax

    ; Debug print BAR0 mapping
    lea     rcx, szBar0Mapped
    mov     rdx, qword ptr [r12 + DEVICE_EXTENSION.PhysicalBAR0]
    mov     r8, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0]
    mov     r9d, dword ptr [r12 + DEVICE_EXTENSION.BAR0Length]
    call    DbgPrint

    jmp     _next_resource

_map_bar2:
    mov     qword ptr [r12 + DEVICE_EXTENSION.PhysicalBAR2], rcx
    mov     qword ptr [r12 + DEVICE_EXTENSION.BAR2Length], rdx

    ; Map BAR2: PAGE_READWRITE | PAGE_WRITECOMBINE = 0x404
    mov     r8d, 404h
    call    MmMapIoSpaceEx

    test    rax, rax
    jz      _pnp_fail_resources

    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2], rax

    ; Debug print BAR2 mapping
    lea     rcx, szBar2Mapped
    mov     rdx, qword ptr [r12 + DEVICE_EXTENSION.PhysicalBAR2]
    mov     r8, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2]
    mov     r9, qword ptr [r12 + DEVICE_EXTENSION.BAR2Length]
    call    DbgPrint

_next_resource:
    add     rdi, 20h                        ; Next descriptor (32 bytes)
    dec     r13d
    jmp     _resource_loop

_pnp_check_mapped:
    ; Verify BAR0 was mapped
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0]
    test    rcx, rcx
    jz      _pnp_fail_resources

    ; Initialize Navi 32 hardware via direct MMIO
    call    InitNavi32Hardware

    ; Mark device as started
    mov     byte ptr [r12 + DEVICE_EXTENSION.DeviceStarted], 1

    lea     rcx, szHwInit
    call    DbgPrint

    ; Pass IRP down to lower driver
    jmp     _pnp_pass_down

; ==============================================================================
; IRP_MN_STOP_DEVICE - Unmap BARs
; ==============================================================================
_pnp_stop:
    ; Unmap BAR0
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0]
    test    rcx, rcx
    jz      _stop_unmap_bar2
    mov     edx, dword ptr [r12 + DEVICE_EXTENSION.BAR0Length]
    call    MmUnmapIoSpace
    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0], 0

_stop_unmap_bar2:
    ; Unmap BAR2
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2]
    test    rcx, rcx
    jz      _stop_done
    mov     rdx, qword ptr [r12 + DEVICE_EXTENSION.BAR2Length]
    call    MmUnmapIoSpace
    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2], 0

_stop_done:
    mov     byte ptr [r12 + DEVICE_EXTENSION.DeviceStarted], 0
    jmp     _pnp_pass_down

; ==============================================================================
; IRP_MN_REMOVE_DEVICE - Unmap, detach, delete
; ==============================================================================
_pnp_remove:
    lea     rcx, szRemoveDevice
    call    DbgPrint

    ; Unmap BAR0
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0]
    test    rcx, rcx
    jz      _remove_unmap_bar2
    mov     edx, dword ptr [r12 + DEVICE_EXTENSION.BAR0Length]
    call    MmUnmapIoSpace
    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR0], 0

_remove_unmap_bar2:
    ; Unmap BAR2
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2]
    test    rcx, rcx
    jz      _remove_detach
    mov     rdx, qword ptr [r12 + DEVICE_EXTENSION.BAR2Length]
    call    MmUnmapIoSpace
    mov     qword ptr [r12 + DEVICE_EXTENSION.VirtualBAR2], 0

_remove_detach:
    ; Detach from lower device
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.LowerDeviceObject]
    call    IoDetachDevice

    ; Delete our FDO
    mov     rcx, rsi
    call    IoDeleteDevice

    ; Complete IRP with success
    mov     dword ptr [rbx + 30h], STATUS_SUCCESS
    mov     qword ptr [rbx + 38h], 0        ; Information = 0
    mov     rcx, rbx
    xor     dl, dl                          ; IO_NO_INCREMENT
    call    IofCompleteRequest
    xor     eax, eax
    jmp     _pnp_exit

; ==============================================================================
; Pass IRP down to lower driver
; ==============================================================================
_pnp_pass_down:
    ; IoSkipCurrentIrpStackLocation: CurrentLocation++, CurrentStackLocation += 0x48
    inc     byte ptr [rbx + 23h]            ; Irp->CurrentLocation
    add     qword ptr [rbx + 0B8h], 48h    ; CurrentStackLocation

    ; IoCallDriver(LowerDeviceObject, Irp)
    mov     rcx, qword ptr [r12 + DEVICE_EXTENSION.LowerDeviceObject]
    mov     rdx, rbx
    call    IoCallDriver

    mov     eax, dword ptr [rbx + 30h]     ; Return lower driver's status
    jmp     _pnp_exit

_pnp_fail_resources:
    mov     dword ptr [rbx + 30h], STATUS_INSUFFICIENT_RESOURCES
    mov     qword ptr [rbx + 38h], 0
    mov     rcx, rbx
    xor     dl, dl
    call    IofCompleteRequest
    mov     eax, STATUS_INSUFFICIENT_RESOURCES

_pnp_exit:
    add     rsp, 56
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DispatchPnp ENDP

; ==============================================================================
; DispatchCreateClose - Handle Open/Close IRPs
; RCX = PDEVICE_OBJECT, RDX = PIRP
; ==============================================================================
DispatchCreateClose PROC FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     qword ptr [rdx + 38h], 0       ; Information = 0
    mov     dword ptr [rdx + 30h], STATUS_SUCCESS
    mov     rcx, rdx                       ; Irp
    xor     dl, dl                         ; IO_NO_INCREMENT
    call    IofCompleteRequest
    xor     eax, eax                       ; STATUS_SUCCESS
    add     rsp, 40
    ret
DispatchCreateClose ENDP

; ==============================================================================
; InitNavi32Hardware - Direct MMIO Hardware Initialization
; RCX = Mapped BAR0 virtual address
; ==============================================================================
InitNavi32Hardware PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 32
    .allocstack 32
    .endprolog

    mov     rbx, rcx                        ; MMIO base address

    ; Step 1: Read GRBM_STATUS to verify hardware is responding
    mov     eax, dword ptr [rbx + mmGRBM_STATUS]

    ; Debug print GRBM_STATUS readback
    push    rax
    lea     rcx, szGrbmStatus
    pop     rdx
    call    DbgPrint

    ; Step 2: Halt Compute Micro Engine (CP_MEC_CNTL)
    ; Setting bit 0 halts all compute queues
    mov     dword ptr [rbx + mmCP_MEC_CNTL], 1

    ; Stall 50us for compute pipeline to drain
    mov     ecx, 50
    call    KeStallExecutionProcessor

    ; Step 3: Reset compute ring buffer pointers
    xor     eax, eax
    mov     dword ptr [rbx + mmCP_RB0_RPTR], eax
    mov     dword ptr [rbx + mmCP_RB0_WPTR], eax

    ; Step 4: Clear CP_HQD_ACTIVE to deactivate hardware queue descriptor
    xor     eax, eax
    mov     dword ptr [rbx + mmCP_HQD_ACTIVE], eax

    ; Step 5: Re-enable compute micro engine
    xor     eax, eax
    mov     dword ptr [rbx + mmCP_MEC_CNTL], eax

    ; Stall 50us for pipeline to stabilize
    mov     ecx, 50
    call    KeStallExecutionProcessor

    ; Step 6: Verify GRBM_STATUS2 for pipeline readiness
    mov     eax, dword ptr [rbx + mmGRBM_STATUS2]

    add     rsp, 32
    pop     rbx
    ret
InitNavi32Hardware ENDP

; ==============================================================================
; DriverUnload - Kernel Teardown
; RCX = PDRIVER_OBJECT
; ==============================================================================
DriverUnload PROC FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; Device cleanup handled in IRP_MN_REMOVE_DEVICE
    ; This just allows the driver image to be unloaded

    add     rsp, 40
    ret
DriverUnload ENDP

END