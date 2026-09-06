// Win32IDE_ShellLayout.hpp — phased left-to-right shell rebuild (P1_UI_SHELL_LAYOUT_001)
#pragma once

#include <windows.h>

class Win32IDE;

namespace RawrXD::ShellLayout {

// Ladder (P1_UI_SHELL_LAYOUT_001):
//   0=frame  1=activity  2=sidebar  3=editor  4=status
//   5=RESERVED terminal stub — NOT_TESTED / UNIMPLEMENTED (do not silent-skip in evidence)
//   6=legacy full spatial (split 6A/6B/6C if FAIL; do not reopen PASS 0–4)
int PhaseFromEnvironment();
bool RebuildActive();
bool UseLegacySpatial(int phase);

// Persistent visibility policy (not a one-shot HideAllChrome).
// Rebuild PHASE N => only allow-listed chrome roots (and their descendants) may be visible.
bool FrameOnlyMode();
bool RebuildRestrictActive();  // rebuild && phase 0..4
void EnsurePolicyInstalled(HWND mainHwnd);
void ApplyChromeVisibilityPolicy(HWND mainHwnd);
void RegisterAllowedRoots(HWND activity, HWND sidebar, HWND editor, HWND status);
bool SetChildVisible(HWND child, bool visible, const char* callsite);

// Register from IDE getters then ApplyChromeVisibilityPolicy.
void ApplyFromIde(Win32IDE* ide);

void LayoutIDE(Win32IDE* ide, int clientW, int clientH);

}  // namespace RawrXD::ShellLayout
