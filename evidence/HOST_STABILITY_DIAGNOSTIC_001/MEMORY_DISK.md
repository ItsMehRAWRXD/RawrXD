# MEMORY_DISK — HOST_STABILITY_DIAGNOSTIC_001

Source: `raw/memory_disk.txt` (CIM Win32_OperatingSystem / PageFileUsage / PSDrive)

## Memory

| Metric | Value |
|--------|------:|
| TotalVisibleMemory | ≈ 63094.3 MB |
| FreePhysicalMemory | ≈ 39402.4 MB |
| TotalVirtualMemory | ≈ 126582.3 MB |
| FreeVirtualMemory | ≈ 91211.2 MB |

## Pagefile (`C:\pagefile.sys`)

| Metric | Value |
|--------|------:|
| AllocatedBaseSize | 63488 MB |
| CurrentUsage | 84 MB |
| PeakUsage | 96 MB |

## Disk free

| Volume | Used | Free |
|--------|-----:|-----:|
| C: | ≈ 431.46 GB | ≈ 496.61 GB |
| F: | ≈ 3242.57 GB | ≈ 483.32 GB |

## Assessment

No memory pressure or disk-full condition at capture time. Does **not** support HOST_UNSTABLE.
