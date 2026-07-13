# RawrXD Changelog

All notable changes to RawrXD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🚀 Features
- Phase F.1 Production Release infrastructure
- Cross-platform installer builder (MSI, DMG, AppImage)
- Automated benchmark execution pipeline
- GitHub Actions release automation
- Docker containerization support

### ⚡ Performance
- SIS (Sovereign Intelligence Score) framework
- SAI (Sovereign Advantage Index) for comparative analysis
- Statistical significance testing with Welch's t-test
- Expected Grade A performance (85+ SIS)

### 🔧 Infrastructure
- WiX Toolset integration for Windows MSI
- create-dmg for macOS DMG creation
- appimagetool for Linux AppImage
- Code signing and checksum generation
- Package manager manifests (Homebrew, Chocolatey, winget)

---

# RawrXD IDE v1.0.0-Stable
**"The Native Standard"**
**Release Date:** 2026-06-22  
**Build Status:** Gold Master ✅

---

## 🚀 Key Features

* **Core:** Pure Win32 + MASM x64. Zero dependencies.
* **LSP Integration:** First-class support for `clangd`, `pyright`, and `rust-analyzer`.
* **Intelligence:** Native Command Palette (Ctrl+Shift+P), Quick Open, and File Explorer.
* **Performance:** Optimized GDI painting pipeline with zero-flicker overlays.
* **Architecture:** "Gold Master" status—fully audit-hardened and stability-proven.

---

## 🛠 Fixes & Hardening (v1.0.0)

### Critical
* **Fixed:** Color-key transparency collision in Annotation Overlay (moved to RGB(1,1,1)).
  * *File:* `Win32IDE_Annotations.cpp`
  * *Issue:* Pure black `RGB(0,0,0)` conflicted with `BLACK_BRUSH`, causing entire overlay to become transparent.
  * *Solution:* Use near-black `RGB(1,1,1)` for color-key transparency.

### Medium
* **Fixed:** Flicker-free painting enforced across all overlays.
  * *Files:* `Win32IDE_PeekOverlay.cpp`, `Win32IDE_DiffView.cpp`, `Win32IDE_Tier2Cosmetics.cpp`, `Win32IDE.cpp`
  * *Pattern:* All overlay window procedures now return 1 from `WM_ERASEBKGND` to prevent default background erase.

### Low
* **Fixed:** GDI resource management in floating panels.
  * *Pattern:* Per-paint brushes now properly cleaned up with `DeleteObject()`.

---

## 📈 Metrics

| Metric | Value |
|--------|-------|
| Dependencies | 0 |
| Runtime | Native Win32 |
| Architecture | x64 (Win32 + MASM) |
| Stability | Gold Master (Verified) |
| Transparency Issues | 0 (Fixed) |
| Flicker Issues | 0 (Fixed) |
| GDI Leaks (Critical) | 0 |

---

## 🎯 Technical Highlights

### GDI/Painting Pipeline Hardening
- Color-key transparency uses industry-standard `RGB(1,1,1)` to avoid pure black collision
- Consistent `WM_ERASEBKGND: return 1;` pattern across all overlay windows
- Proper brush lifecycle management (create/use/delete)

### Overlay Windows Fixed
- ✅ Annotation Overlay (diagnostic annotations)
- ✅ Peek Overlay (Alt+F12 definition peek)
- ✅ Diff Panel (side-by-side diff view)
- ✅ Git Diff Panel (source control diff)
- ✅ Floating Panel (bottom panel)
- ✅ Ghost Text Overlay (inline completions)
- ✅ Agent Diff Panel (agent edit review)

---

## 🏆 Gold Master Verification

### Build Verification
- [x] Clean rebuild from scratch
- [x] No stale object files
- [x] All compilation units successful

### Runtime Verification
- [x] Annotation overlay renders correctly (no black box)
- [x] Peek overlay shows without flicker
- [x] Diff panels render smoothly
- [x] Floating panel resizes without artifacts
- [x] Ghost text overlay displays correctly

### Resource Monitoring
- [x] GDI Objects count stable during overlay toggling
- [x] No memory growth during extended use
- [x] Command palette shows/hides correctly

---

## 📝 Known Technical Debt (Non-Critical)

### Activity Bar Brushes
- **Location:** `Win32IDE_VSCodeUI.cpp`
- **Issue:** 3 class-level brushes (`m_actBarBackgroundBrush`, `m_actBarHoverBrush`, `m_actBarActiveBrush`) not explicitly deleted
- **Impact:** Low - OS reclaims resources on process exit
- **Planned Fix:** v1.0.1 maintenance release

### Command Palette Class Brush
- **Location:** `Win32IDE_Commands.cpp`
- **Issue:** Class background brush set via `SetClassLongPtrA` not explicitly freed
- **Impact:** Low - single brush, OS handles cleanup on class unregistration
- **Planned Fix:** v1.0.1 maintenance release

---

## 🙏 Acknowledgments

This release represents the culmination of extensive engineering effort to create a zero-dependency, native Win32 IDE that rivals modern web-based alternatives in features while maintaining the performance and stability that only native code can provide.

**Engineering Philosophy:**
- Zero external dependencies
- Pure Win32 API + MASM x64
- First-class LSP support
- Performance-first architecture
- Long-term maintainability

---

## 📦 Installation

### Requirements
- Windows 10/11 (x64)
- Visual Studio 2022 (for build from source)
- No additional runtime dependencies

### Build from Source
```bash
# Clone repository
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Clean build
rm -rf build-ninja/
mkdir build-ninja && cd build-ninja
cmake .. -G Ninja
ninja -j$(nproc)

# Output: RawrXD-Win32IDE.exe
```

---

## 🔧 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 1903+ | Windows 11 23H2+ |
| Architecture | x64 | x64 |
| RAM | 4 GB | 8 GB+ |
| GPU | DirectX 11 capable | Vulkan compatible |
| Storage | 100 MB | 500 MB+ |

---

## 📜 License

[License information here]

---

**Version:** v1.0.0-Stable  
**Codename:** "The Native Standard"  
**Status:** Gold Master ✅  
**Release Date:** 2026-06-22

---

*"Twenty years from now, this will still compile and run flawlessly."*
