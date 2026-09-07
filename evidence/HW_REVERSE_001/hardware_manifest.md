# UCF Hardware Reconciliation & Topology Manifest

**Gate:** `HW_REVERSE_001`  
**Node:** `DESKTOP-89OE3D8`  
**Fill law:** `REAL probe → keep` · `contradictory / missing / tool-absent → uncoherent` · never invent DDR timings, GDDR from WMI, or NUMA.

**UCF axioms enforced here:** UCF-001 (pointer/OS descriptor ≠ identity), UCF-010 (host staging must replace unavailable P2P), UCF-012 (no vendor/index lock-in), UCF-013 (unknown → measured).

---

## 1. Reconciled topology matrix (summary)

| Role | Identity | Status |
|------|----------|--------|
| Host CPU | AMD Ryzen 7 **7800X3D** (8C/16T, 96 MiB L3) | **REAL** |
| DRAM | **4×16 GB** Crucial `CP16G56C46U5.C8D` @ **5600** MT/s (~63.1 GB visible) | **REAL** |
| Host staging pool (climb) | ~38–42 GB class (`ramAvail` prior) | **REAL** (prior climb) |
| Primary accel (climb-bound) | **AI PRO R9700** — host-visible ~31.9 GiB aligns with `vram≈32476 MB` | **MEASURED** (Vulkan) / bind still **uncoherent** without live `RAWRXD_GPU_*` |
| Secondary accel | **RX 7800 XT** — host-visible ~16.0 GiB; physical 16 GB GDDR6 expected | **MEASURED** host-visible; device-local ~47.1 GiB = **SKU-suspect** (WDDM pool) |
| Tertiary | Radeon Graphics iGPU — ~15.8 GiB UMA-ish | **MEASURED** (Vulkan) |
| Workspace | `G:\~dev` on Micron CT4000X10PROSSD9 (USB) disk **4** | **REAL** |
| K2 shards | `F:` on Micron CT4000X10PROSSD9 (USB) disk **3** | **REAL** |

---

## 2. Platform

| Field | Value | Status |
|-------|-------|--------|
| Host | `DESKTOP-89OE3D8` | REAL |
| Board | ASRock **X870E Taichi** | REAL |
| BIOS | AMI **4.43** | REAL |
| OS | Windows 11 Home **10.0.26200** x64 | REAL |
| Chassis / asset | — | **uncoherent** |

---

## 3. CPU

| Field | Value | Status |
|-------|-------|--------|
| Model | AMD Ryzen 7 **7800X3D** | REAL |
| ID | Family 25 Model 97 Stepping 2 | REAL (prior) |
| Cores / threads | **8 / 16** | REAL |
| Socket | AM5 | REAL |
| L2 / L3 | 8 MiB / **96 MiB** | REAL (WMI KiB → MiB) |
| Max clock (WMI) | 4201 MHz | REAL (boost ceiling may differ) |
| Virt firmware | True | REAL (prior) |
| NUMA | single-socket expected | **uncoherent** (`Win32_NumaNode` missing) |
| Exact CCD geometry | — | **uncoherent** |
| Package TDP / PPT | — | **uncoherent** |
| AVX-512 / VNNI / BF16 | Zen 4 **architecture-expected**; this-pass `__cpuidex` **not executed** (MSVC include env absent) | **uncoherent** until CPUID leaf 7 witness lands |

> Do **not** treat “Zen 4 has AVX-512” marketing copy as a climb seal. Host packed Q6 path may use AVX2 and/or AVX-512; seal only after CPUID + kernel path witness.

---

## 4. DRAM / host staging

| Field | Value | Status |
|-------|-------|--------|
| Visible RAM | ~63.1 GB class | REAL (prior + consistent) |
| Modules | 4× Crucial `CP16G56C46U5.C8D` | REAL |
| Channels | P0 CHANNEL A ×2, P0 CHANNEL B ×2 | REAL |
| Reported speed | **5600** MHz | REAL |
| Form / SMBIOS | DIMM / DDR5-class | REAL (prior) |
| Rank / XMP name / CL-tRCD… | — | **uncoherent** |
| Host staging for UCF-010 | ~38–42 GB avail class from Deep2 elastic prior | REAL (climb), not a reserved carve-out seal |

---

## 5. GPU — WMI vs Vulkan (UCF-001 / UCF-013)

WMI `AdapterRAM` **4 GB** on discrete GPUs is a **32-bit overflow artifact**, not physical identity.

| Device | WMI AdapterRAM | Vulkan device-local | Vulkan host-visible | Role |
|--------|----------------|---------------------|---------------------|------|
| iGPU Radeon Graphics | 0.5 GB (suspect) | ~15.8 GiB (UMA-ish) | ~31.6 GiB | tertiary |
| **AI PRO R9700** | 4 GB (**overflow**) | ~47.1 GiB (**WDDM-pool suspect**) | **~31.9 GiB** | **primary climb candidate** (`vram≈32476 MB`) |
| **RX 7800 XT** | 4 GB (**overflow**) | ~47.1 GiB (**SKU-suspect**) | ~16.0 GiB | secondary |

| Field | Status |
|-------|--------|
| Which GPU owns climb `vram≈32476MB` | **uncoherent** without live device bind probe (R9700 host-visible is best match) |
| nvidia-smi / CUDA | **uncoherent** (absent — AMD path) |
| amd-smi / rocm-smi | **uncoherent** (not installed) |
| Vulkan | **1.4.x**, AMD proprietary **26.8.1** (prior) |
| Solo vs multi-GPU decode binding | **uncoherent** |
| True device-local via `VK_EXT_memory_budget` | **uncoherent** this pass (probe template only) |
| P2P R9700 ↔ 7800 XT | **uncoherent** → assume **host-mediated** (UCF-009/010) |

---

## 6. Storage — BusType now MEASURED

`Get-PhysicalDisk` (this pass) clears prior SCSI-mask ambiguity for internal SSDs:

| DeviceId | FriendlyName | BusType | Media | Size |
|----------|--------------|---------|-------|------|
| 0 | CT1000P3PSSD8 | **NVMe** | SSD | ~931.5 GB |
| 1 | CT1000P3PSSD8 | **NVMe** | SSD | ~931.5 GB |
| 2 | CT1000P3PSSD8 | **NVMe** | SSD | ~931.5 GB |
| 3 | Micron CT4000X10PROSSD9 | **USB** | SSD | ~3726 GB |
| 4 | Micron CT4000X10PROSSD9 | **USB** | SSD | ~3726 GB |

### Volume map (this pass)

| Letter | DiskNumber | Size | Free (prior/class) | Role |
|--------|------------|------|--------------------|------|
| **C:** | **uncoherent** (volume 929.1 GB; disk 0 not returned by `Get-Disk` this pass) | ~929 GB | ~573 GB | OS |
| **D:** | 2 | ~931 GB | full-ish prior | NVMe scratch |
| **E:** | 1 | ~931 GB | **0 free** prior | staging / immutable |
| **F:** | 3 (USB Micron) | ~3.7 TB | ~98 GB prior | **K2 shards** |
| **G:** | 4 (USB Micron) | ~3.7 TB | ~1618 GB prior | **`G:\~dev` workspace** |

| Field | Status |
|-------|--------|
| SMART / PCIe gen / link width | **uncoherent** |
| Disk 0 ↔ C: definitive map | **uncoherent** this pass |

---

## 7. Network (prior)

| Adapter | MAC | Speed | Status |
|---------|-----|-------|--------|
| RZ717 WiFi 7 | 48:45:E6:35:47:DD | 144.4 Mbps assoc | REAL (prior) |
| Realtek 5GbE | 9C:6B:00:F5:75:B9 | WMI overflow | capability **uncoherent** this pass |
| Duplex / MTU / NUMA IRQ | — | **uncoherent** |

---

## 8. Deep2 climb coupling (prior REAL runs)

| Field | Value | Status |
|-------|-------|--------|
| Elastic `vram=` | **32476 MB** | REAL (prior) |
| Elastic `ramAvail≈` | ~38–42 GB | REAL (prior) |
| `DEEP2_K2_GPU_MLA=1` bound GPU | — | **uncoherent** until live bind |
| Host Q6 / logits path ISA | AVX2 known-in-tree; AVX-512 | **uncoherent** until CPUID + path seal |

### Logits split fold (conversation claim — not re-sealed here)

| Claim | Treat as |
|-------|----------|
| Logits ~47–49 ms/tok vs ~91–130 | **requires** live `K2_LOGITS_*` gate re-run on this tree |
| GPU RANGE_ARGMAX hidden under CPU F32 branch | topology hypothesis — seal with wall witnesses |
| `DEEP2_LOGITS_GPU_CUT` raise toward equilibrium | next ROO **if** logits gate PASS and GPU branch still shorter |
| Shader-side argmax (index+scalar only) | next AFTER cut balance |
| Port split topology to Q4 `q_a`/`q_b` | **only after** logits fold sealed; Q-branch owner from `_006` remains `q_a` kernel under MLA |

---

## 9. Answers for next-fold tuning (from this host map)

| Question | Answer |
|----------|--------|
| GPU + VRAM constraints? | Climb VRAM class **~32 GB host-visible** on **R9700 candidate**; second card **~16 GB** host-visible (7800 XT). Do not trust WMI 4 GB. Multi-GPU P2P **uncoherent** → host bounce. |
| CPU Q6 GEMV: core vs bandwidth? | **uncoherent** without roofline witness. Clues: 7800X3D **96 MiB L3** favors reuse; DDR5-5600 2DPC can still bound streaming Q6 row walks over 160k vocab. Seal with counters: `LOGITS_DOT_MS` vs DRAM BW probe / L3 miss proxy. |

---

## 10. Still-needed micro-probes (UCF-013)

1. `VK_EXT_memory_budget` per physical device → true local vs budget.  
2. Live `DEEP2` / Vulkan device name for climb bind.  
3. CPUID leaf 7 (+7.1) under full MSVC env → AVX-512F/DQ/BW/VL/VNNI/BF16 bits.  
4. `Get-Disk`/`Get-Partition` for disk **0** ↔ **C:**.  
5. Optional: PCIe link width/gen via vendor tool (not installed → currently uncoherent).

---

*Witness written for `evidence/HW_REVERSE_001/`. Fold-bank climb artifacts stay out of this directory.*
