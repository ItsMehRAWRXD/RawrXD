# SovereignK.sys — Kernel-Mode GPU Bridge Driver

## Overview

SovereignK is a Windows kernel-mode driver that provides direct access to AMD GPU VRAM via PCIe BAR mapping. It bypasses the WDDM/DirectX stack to achieve maximum throughput for inference workloads.

**Target Hardware:** AMD Radeon RX 7800 XT (Navi 32, Device ID 0x747E)  
**Architecture:** x64 Kernel Mode Driver (KMDF)  
**Purpose:** Zero-copy DMA from host Sovereign Arena to GPU VRAM

## Architecture

```
User Mode                    Kernel Mode                    Hardware
----------                   -----------                    --------
RawrXD App  ──IOCTL──>  SovereignK.sys  ──MmMapIoSpace──>  GPU VRAM BAR
     │                            │
     └─Sovereign Arena──────MmProbeAndLockPages──┘
```

## Components

### Driver Files (`src/kernel/SovereignK/`)

| File | Purpose |
|------|---------|
| `SovereignK.h` | Main header with structures and IOCTLs |
| `SovereignK.c` | Driver entry point and IOCTL dispatch |
| `BarMapping.c` | `MmMapIoSpace` BAR0 mapping |
| `HostMemory.c` | `MmProbeAndLockPages` for DMA buffers |
| `DmaTransfer.c` | DMA transfer with RDTSC timing |
| `Utils.c` | Memory allocation helpers |
| `SovereignK.vcxproj` | Visual Studio project file |
| `sources` | WDK build file (alternative) |

### Client Files

| File | Purpose |
|------|---------|
| `include/SovereignK_Client.h` | User-mode client interface |
| `src/core/SovereignK_Client.cpp` | Client implementation |

## Build Instructions

### Prerequisites

1. **Windows Driver Kit (WDK)** — Install from Microsoft
2. **Visual Studio 2022** with Windows Driver development workload
3. **Test Signing Enabled** — Required to load unsigned driver

### Enable Test Signing

```powershell
# Run as Administrator
bcdedit /set testsigning on
# Reboot required
```

### Build with Visual Studio

1. Open `src\kernel\SovereignK\SovereignK.vcxproj` in Visual Studio
2. Select **Release** | **x64**
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: `x64\Release\SovereignK.sys`

### Build with WDK (Command Line)

```powershell
# Open "Developer Command Prompt for VS 2022" as Administrator
cd d:\rawrxd\src\kernel\SovereignK
build -ceZ
```

## Installation

### Manual Installation

```powershell
# Run as Administrator

# Copy driver to system directory
copy x64\Release\SovereignK.sys C:\Windows\System32\drivers\

# Create service
sc create SovereignK type= kernel binPath= C:\Windows\System32\drivers\SovereignK.sys

# Start driver
sc start SovereignK

# Verify
sc query SovereignK
```

### Using INF (Recommended)

Create `SovereignK.inf`:

```inf
[Version]
Signature="$WINDOWS NT$"
Class=System
ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}
Provider=%ManufacturerName%
CatalogFile=SovereignK.cat
DriverVer=1.0.0.0

[Manufacturer]
%ManufacturerName%=Standard,NTamd64

[Standard.NTamd64]
%DeviceDesc%=SovereignK_Device, Root\SovereignK

[SovereignK_Device.NT]
CopyFiles=DriversDir

[DriversDir]
SovereignK.sys

[DestinationDirs]
DriversDir=12

[SourceDisksNames]
1=%DiskName%,,,""

[SourceDisksFiles]
SovereignK.sys=1

[SovereignK_Device.NT.Services]
AddService=SovereignK,0x00000002,SovereignK_Service

[SovereignK_Service]
DisplayName    = %ServiceDesc%
ServiceType    = 1
StartType      = 3
ErrorControl   = 1
ServiceBinary  = %12%\SovereignK.sys

[Strings]
ManufacturerName="RawrXD"
ServiceDesc="Sovereign Kernel Driver"
DeviceDesc="Sovereign GPU Bridge"
DiskName="SovereignK Installation Disk"
```

Install:
```powershell
# Right-click INF → Install
# Or:
pnputil /add-driver SovereignK.inf /install
```

## Usage

### C++ Client Example

```cpp
#include "SovereignK_Client.h"
#include <cstdio.h>

int main() {
    rxdn::SovereignKClient client;
    
    // Open driver
    if (!client.Open()) {
        printf("Failed to open driver: %s\n", client.GetLastError());
        return 1;
    }
    
    // Map GPU BAR0 (physical address from PCI config)
    // For RX 7800 XT, BAR0 is typically at a high physical address
    uint64_t bar0Physical = 0x00000000; // Get from PCI config
    if (!client.MapBAR(bar0Physical, 256 * 1024 * 1024, 2)) { // 2 = WriteCombined
        printf("Failed to map BAR: %s\n", client.GetLastError());
        return 1;
    }
    
    // Lock host memory for DMA
    void* hostBuffer = _aligned_malloc(4096, 64);
    uint64_t hostPhys;
    HANDLE lockHandle;
    client.LockHostMemory(hostBuffer, 4096, false, &hostPhys, &lockHandle);
    
    // Perform DMA transfer
    uint64_t cycles;
    client.DMATransfer(hostPhys, 0, 4096, &cycles); // To GPU offset 0
    printf("DMA completed in %llu cycles\n", cycles);
    
    // Cleanup
    client.UnlockHostMemory(lockHandle);
    client.UnmapBAR();
    client.Close();
    
    return 0;
}
```

## IOCTL Reference

| IOCTL | Input | Output | Purpose |
|-------|-------|--------|---------|
| `IOCTL_SOVEREIGNK_MAP_BAR` | `SOVEREIGNK_BAR_REQUEST` | `SOVEREIGNK_BAR_RESPONSE` | Map GPU BAR |
| `IOCTL_SOVEREIGNK_UNMAP_BAR` | None | None | Unmap BAR |
| `IOCTL_SOVEREIGNK_LOCK_HOST` | `SOVEREIGNK_LOCK_REQUEST` | `SOVEREIGNK_LOCK_RESPONSE` | Pin host memory |
| `IOCTL_SOVEREIGNK_UNLOCK_HOST` | Handle | None | Unpin memory |
| `IOCTL_SOVEREIGNK_DMA_TRANSFER` | `SOVEREIGNK_DMA_REQUEST` | `SOVEREIGNK_DMA_RESPONSE` | Execute DMA |
| `IOCTL_SOVEREIGNK_GET_STATS` | None | `SOVEREIGNK_STATS` | Get statistics |

## Cache Policy

The driver supports two cache policies for BAR mapping:

| Value | Policy | Use Case |
|-------|--------|----------|
| 0 | `MmNonCached` | Safe default, no caching |
| 2 | `MmWriteCombined` | **Recommended** for VRAM writes |

**Write-Combining (WC)** is critical for GPU VRAM performance. It allows the CPU to combine multiple writes into cache lines before sending them over PCIe, maximizing bus utilization.

## Security Considerations

⚠️ **WARNING: This driver provides direct hardware access**

- Only load on development/test systems
- Requires Administrator privileges
- Can cause system instability if misused
- Never deploy to production without proper signing

## Troubleshooting

### Driver Won't Load

```powershell
# Check test signing
bcdedit /enum | findstr test

# Must show: test Yes
```

### DeviceIoControl Fails

```powershell
# Check driver status
sc query SovereignK

# Check Event Log
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7000,7001}
```

### BSOD on DMA

- Verify physical addresses are correct
- Ensure alignment requirements met (64-byte host, 256-byte GPU)
- Check BAR is actually mapped before DMA

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| BAR Map Time | < 1ms | TBD |
| DMA Latency | < 10μs | TBD |
| Throughput | 50 GB/s | TBD |
| CPU Overhead | < 1% | TBD |

## Next Steps

1. ✅ Driver skeleton complete
2. ⬜ Build and sign driver
3. ⬜ Load driver with test signing
4. ⬜ Run integration test with RawrXD
5. ⬜ Measure actual DMA latency
6. ⬜ Optimize with MASM REP MOVSQ
7. ⬜ Add interrupt handling for async completion

## References

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [MmMapIoSpace](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/mm-mapiospace)
- [MmProbeAndLockPages](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/mm-probe-and-lock-pages)
- [PCI BAR Programming](https://wiki.osdev.org/PCI)

---

**RawrXD Sovereign Architecture — Phase 3: Kernel Mode**  
*Bridging the gap between user-mode inference and silicon-level performance*
