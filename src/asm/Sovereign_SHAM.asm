; ==============================================================================
; SOVEREIGN HARDWARE ABSTRACTION MAP (SHAM)
; File: Sovereign_SHAM.asm
; Role: Physical Memory Envelope & IOMMU Topology Constraints
; ==============================================================================

.DATA
    ALIGN 4096
    ; -------------------------------------------------------------
    ; Fixed Physical Layout Contract
    ; -------------------------------------------------------------
    ; 0x0000_0000 – 0x000F_FFFF   Reserved (IVT / BIOS remnants)
    ; 0x0010_0000 – 0x0FFF_FFFF   Kernel Control Plane (Sovereign Gov)
    ; 0x1000_0000 – 0x7FFF_FFFF   Sovereign Arena (NUMA-aligned heap)
    ; 0x8000_0000 – 0x8FFF_FFFF   Shadow Map + DAG State
    ; 0x9000_0000 – 0x9FFF_FFFF   Ghost Trace Circular Buffer
    ; 0xA000_0000 – 0xAFFF_FFFF   DMA Tensor Window (NVMe / GPU shared)
    ; 0xB000_0000 – 0xFFFF_FFFF   MMIO / Device Region
    
    SHAM_KERNEL_PLANE   QWORD 000100000h
    SHAM_ARENA_BASE     QWORD 010000000h
    SHAM_SHADOW_MAP     QWORD 080000000h
    SHAM_GHOST_TRACE    QWORD 090000000h
    SHAM_DMA_WINDOW     QWORD 0A0000000h
    SHAM_MMIO_REGION    QWORD 0B0000000h
