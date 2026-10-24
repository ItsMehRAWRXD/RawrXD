# RawrXD IDE completion roadmap — moves 121–150

These are acceptance targets, NOT implemented features. Preserve existing F:/rawrxd sources and compare against receipts before changing files.

| Move | Goal | Mandatory acceptance |
|---:|---|---|
| 121 | Recursive HWND readiness and stable control IDs | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 122 | Real editor insert/undo/redo and file persistence | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 123 | Selection/syntax highlighter differential tests | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 124 | Multi-tab workspace and unsaved-change recovery | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 125 | File explorer move/rename/delete safety | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 126 | Search/replace project-scale correctness | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 127 | Terminal async output/cancel/Job Object cleanup | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 128 | PowerShell process lifecycle and error surfaces | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 129 | Debugger breakpoint/step/watch true behavior | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 130 | Git stage/diff/commit guarded workflow | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 131 | VSIX manifest parse and dependency resolution | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 132 | JS extension host supported API matrix | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 133 | Extension isolation and permission policy | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 134 | Chat and GhostText simultaneous inference | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 135 | Ollama-driven agent tool E2E | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 136 | Deep2 Q2_K FFN_UP true GPU parity | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 137 | Phi-3 GPU AV isolation and memory safety | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 138 | Agent edit/build/test/rollback transactional proof | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 139 | Snapshots created/removed/modified files and crash recovery | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 140 | Native compiler/linker cross-target smoke | Demonstrate real operations in the production IDE, capture command, source revision, logs, and checksums; independent negative-case test passes. |
| 141 | ELF/Mach-O/PE object and relocation fixtures | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 142 | IDE signing command + identity authorization | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 143 | Signing job cancellation and private-key safety | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 144 | Extension command to IDE builder bridge | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 145 | DPI/accessibility/theme/visual testing | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 146 | Session restore after fault injection | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 147 | VRAM/CPU model admission and cancellation quotas | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 148 | Deterministic Qt-free Release build | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 149 | Portable packaging for Windows/Linux/Android/macOS/iOS | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |
| 150 | Independent full IDE certification | Reproduce on the actual selected platform with independently checked outputs, failure diagnostics, and no unapproved dependencies. |

## Blocking order
- First: 121–126 (actual editor and controls), 136–138 (GPU safety and autonomous rollback).
- Then: 127–135, 139–145 (tooling, extension system, signing bridge).
- Finally: 146–150 (quality, deployment, independent certification).

## Non-negotiable evidence
- Every PASS must identify a real test log or receipt; do not mark PASS based on compilation alone.
- Report `NOT_RUN`, `FAIL`, or `BLOCKED` for incomplete gates.
- Apple signing requires valid authorized identity, entitlements, provisioning, and device verification.
- Installed clang/MSVC/Apple/Android SDKs are external build/platform prerequisites even if no libraries are bundled.
- Never claim all-firmware installation or compatibility based only on IPA structure.