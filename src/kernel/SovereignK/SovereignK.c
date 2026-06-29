/*++

Module Name:
    SovereignK.c

Abstract:
    Main driver entry point and IOCTL dispatch for SovereignK.sys
    
    This driver provides:
    1. Physical BAR0 mapping via MmMapIoSpace
    2. Host memory pinning via MmProbeAndLockPages
    3. DMA transfer orchestration
    4. Interrupt handling for completion

Environment:
    Kernel mode only

--*/

#include "SovereignK.h"

// ============================================================================
// Globals
// ============================================================================

PDRIVER_OBJECT g_DriverObject = NULL;

// ============================================================================
// Driver Entry Point
// ============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    PSOVEREIGNK_DEVICE_EXTENSION devExt;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    SovereignK_DbgPrint("DriverEntry: Initializing SovereignK v1.0\n");
    
    g_DriverObject = DriverObject;
    
    // Initialize device name and symlink
    RtlInitUnicodeString(&deviceName, SOVEREIGNK_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, SOVEREIGNK_SYMLINK_NAME);
    
    // Create device object
    status = IoCreateDevice(
        DriverObject,
        sizeof(SOVEREIGNK_DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
        );
    
    if (!NT_SUCCESS(status)) {
        SovereignK_DbgPrint("DriverEntry: IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }
    
    // Initialize device extension
    devExt = (PSOVEREIGNK_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(devExt, sizeof(SOVEREIGNK_DEVICE_EXTENSION));
    
    devExt->DeviceObject = deviceObject;
    devExt->Bar0Mapped = FALSE;
    InitializeListHead(&devExt->HostLockList);
    KeInitializeSpinLock(&devExt->HostLockSpinLock);
    KeInitializeSpinLock(&devExt->StatsLock);
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SovereignKCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SovereignKCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SovereignKDeviceControl;
    DriverObject->DriverUnload = SovereignKDriverUnload;
    
    // Create symbolic link for user-mode access
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        SovereignK_DbgPrint("DriverEntry: IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    SovereignK_DbgPrint("DriverEntry: SovereignK initialized successfully\n");
    SovereignK_DbgPrint("Device: %wZ\n", &deviceName);
    SovereignK_DbgPrint("Symlink: %wZ\n", &symlinkName);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Driver Unload
// ============================================================================

VOID
SovereignKDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT deviceObject;
    PSOVEREIGNK_DEVICE_EXTENSION devExt;
    UNICODE_STRING symlinkName;
    
    UNREFERENCED_PARAMETER(DriverObject);
    
    SovereignK_DbgPrint("DriverUnload: Cleaning up\n");
    
    RtlInitUnicodeString(&symlinkName, SOVEREIGNK_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    
    // Clean up device objects
    deviceObject = DriverObject->DeviceObject;
    while (deviceObject != NULL) {
        devExt = (PSOVEREIGNK_DEVICE_EXTENSION)deviceObject->DeviceExtension;
        
        // Unmap BAR if still mapped
        if (devExt->Bar0Mapped) {
            SovereignK_UnmapBAR(devExt);
        }
        
        // Free any remaining host locks
        // (Should have been freed by user-mode, but clean up anyway)
        
        deviceObject = deviceObject->NextDevice;
    }
    
    // Delete device objects
    deviceObject = DriverObject->DeviceObject;
    while (deviceObject != NULL) {
        PDEVICE_OBJECT nextDevice = deviceObject->NextDevice;
        IoDeleteDevice(deviceObject);
        deviceObject = nextDevice;
    }
    
    SovereignK_DbgPrint("DriverUnload: Cleanup complete\n");
}

// ============================================================================
// Create/Close Handler
// ============================================================================

NTSTATUS
SovereignKCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Device Control Handler (IOCTL Dispatch)
// ============================================================================

NTSTATUS
SovereignKDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    PSOVEREIGNK_DEVICE_EXTENSION devExt;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG ioctlCode;
    
    devExt = (PSOVEREIGNK_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    
    ioctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    
    SovereignK_DbgPrint("DeviceControl: IOCTL 0x%08X\n", ioctlCode);
    
    switch (ioctlCode) {
        
        case IOCTL_SOVEREIGNK_MAP_BAR:
        {
            if (inputBufferLength < sizeof(SOVEREIGNK_BAR_REQUEST) ||
                outputBufferLength < sizeof(SOVEREIGNK_BAR_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = SovereignK_MapBAR(
                devExt,
                (PSOVEREIGNK_BAR_REQUEST)inputBuffer,
                (PSOVEREIGNK_BAR_RESPONSE)outputBuffer
                );
            
            if (NT_SUCCESS(status)) {
                Irp->IoStatus.Information = sizeof(SOVEREIGNK_BAR_RESPONSE);
            }
            break;
        }
        
        case IOCTL_SOVEREIGNK_UNMAP_BAR:
        {
            SovereignK_UnmapBAR(devExt);
            Irp->IoStatus.Information = 0;
            break;
        }
        
        case IOCTL_SOVEREIGNK_LOCK_HOST:
        {
            if (inputBufferLength < sizeof(SOVEREIGNK_LOCK_REQUEST) ||
                outputBufferLength < sizeof(SOVEREIGNK_LOCK_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = SovereignK_LockHostMemory(
                devExt,
                (PSOVEREIGNK_LOCK_REQUEST)inputBuffer,
                (PSOVEREIGNK_LOCK_RESPONSE)outputBuffer
                );
            
            if (NT_SUCCESS(status)) {
                Irp->IoStatus.Information = sizeof(SOVEREIGNK_LOCK_RESPONSE);
            }
            break;
        }
        
        case IOCTL_SOVEREIGNK_UNLOCK_HOST:
        {
            // TODO: Implement unlock
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }
        
        case IOCTL_SOVEREIGNK_DMA_TRANSFER:
        {
            if (inputBufferLength < sizeof(SOVEREIGNK_DMA_REQUEST) ||
                outputBufferLength < sizeof(SOVEREIGNK_DMA_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = SovereignK_DMATransfer(
                devExt,
                (PSOVEREIGNK_DMA_REQUEST)inputBuffer,
                (PSOVEREIGNK_DMA_RESPONSE)outputBuffer
                );
            
            if (NT_SUCCESS(status)) {
                Irp->IoStatus.Information = sizeof(SOVEREIGNK_DMA_RESPONSE);
            }
            break;
        }
        
        case IOCTL_SOVEREIGNK_GET_STATS:
        {
            if (outputBufferLength < sizeof(SOVEREIGNK_STATS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            KIRQL oldIrql;
            KeAcquireSpinLock(&devExt->StatsLock, &oldIrql);
            RtlCopyMemory(outputBuffer, &devExt->Stats, sizeof(SOVEREIGNK_STATS));
            KeReleaseSpinLock(&devExt->StatsLock, oldIrql);
            
            Irp->IoStatus.Information = sizeof(SOVEREIGNK_STATS);
            break;
        }
        
        default:
        {
            SovereignK_DbgPrint("DeviceControl: Unknown IOCTL 0x%08X\n", ioctlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}
