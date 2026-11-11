# BATCH_17 MEMBER_DECL_PLAN

ASOF=2026-11-11T17:39:00Z  
BUILDER=63513ece (sole)  
ASSIST=read-only plan only  
CERTIFIED=0  
PROMOTE=0  
EXE=ABSENT  

Inputs: `ERROR_FREQ_B17_02.txt`, `err_settings.txt`, `err_themes.txt`, `err_termtabs.txt`, `err_memview.txt`, `err_problems.txt`, `rebuild_b17_02.log`, `Win32IDE.h`.  
Constraint: this plan does **not** edit `F:\rawrxd\src` or CMake and does **not** claim a fix.

## Verdict for sole builder

Highest-frequency family is **Win32IDE.h member/type surface vs Batch4/6 TU definitions**, plus a few **signature mismatches** and **non-member source defects**. Many C2065 hits are **cascades** from incomplete `Win32IDE` parse or out-of-line redecl — not true absences.

**Parent already landed:** `AppearanceSettings` + `m_appearance` in `Win32IDE.h` (~L675–683, ~L711). Do **not** re-add.

## Priority order (P01 family first)

1. Add truly missing method decls that `.cpp` defines.
2. Reconcile `addProblem` / `applyTheme` signature drift (decl vs def).
3. Fix non-member blockers (MemoryView namespace typo; Terminal CHARRANGE/include cascade).
4. Do **not** out-of-line-define non-static `m_settings` (err_settings C2761).
5. Defer optional Voice/Attestation/Heap isolate until P01–P06 preserved.

---

## A. Already declared in Win32IDE.h (do not redeclare)

| Symbol | Kind | Header locus (approx) | Notes |
|--------|------|------------------------|-------|
| `OutputSeverity` | nested enum class | ~L397–402 | `Debug/Info/Warning/Error` |
| `appendToOutput` | method | ~L1053 | `(text, tabName="General", severity=Info)` |
| `IDESettings` / `m_settings` | type + member | ~L646–673, ~L710 | **non-static**; no `.cpp` storage |
| `AppearanceSettings` / `m_appearance` | type + member | ~L675–683, ~L711 | **parent already added** |
| `loadSettings` / `saveSettings` | methods | ~L712–713 | C2039 in log likely cascade/stale vs current header |
| `IDETheme` / `m_currentTheme` / `m_themes` | type + members | freestanding ~L369; members ~L2031–2032 | |
| `applyTheme()` | method (0-arg) | ~L1033 | Defined in `Win32IDE.cpp`; keep |
| `m_annotationOverlay` | member | ~L2519 | `unique_ptr<RawrXD::UI::AnnotationOverlay>` |
| `initAnnotationOverlay` / show / hide / isVisible / `addAnnotationOverlayItem` | methods | ~L1150–1154 | |
| `m_hwndProblemsPanel` | member | ~L2661 | |
| `clearProblems` | method | ~L2945 | |
| `addProblem(file,line,col,msg,int)` | method | ~L2944 | **signature differs from ProblemsPanel.cpp** |
| `m_hwndMain` / `m_hInstance` / `m_hwndEditor` | members | ~L1936–1937, ~L677 | |
| `m_terminalTabs` / terminal tab APIs | members/methods | ~L2664–2690 | |
| `IDC_TERMTAB_FIRST` | `#define` | ~L53 (=9310) | Undeclared in err ⇒ include/parse cascade |

`err_settings` C2761 (`Win32IDE::IDESettings Win32IDE::m_settings` redeclaration) means: **never** emit out-of-line storage for this non-static member. Current `Win32IDE_Settings.cpp` comment still mentions “static storage”; sole builder should ensure no such definition remains.

---

## B. Truly missing / must-add declarations (suggested signatures from .cpp)

### B1. Themes — `Win32IDE_Themes.cpp`

| Missing | Suggested declaration | Already elsewhere? |
|---------|----------------------|--------------------|
| `initThemes` | `void initThemes();` | **NO** in `Win32IDE.h` |
| `applyTheme(const std::string&)` | `void applyTheme(const std::string& themeName);` | **Partial:** 0-arg `applyTheme()` exists (~L1033). **Need overload** or rename TU def to avoid C2511 |

Usage evidence (`Win32IDE_Themes.cpp`):
- `void Win32IDE::initThemes()` — uses `m_currentTheme`, `m_appearance`, `m_themes`, `appendToOutput(..., OutputSeverity::Info)`
- `void Win32IDE::applyTheme(const std::string& themeName)` — uses `m_themes`, `m_currentTheme`, `m_appearance`, `m_hwndEditor`, `appendToOutput`, `saveSettings()`

Builder choice: add string overload beside existing 0-arg; keep `Win32IDE.cpp` `applyTheme()` intact.

### B2. Problems — `Win32IDE_ProblemsPanel.cpp`

| Missing / mismatch | Suggested declaration | Already elsewhere? |
|--------------------|----------------------|--------------------|
| `createProblemsPanel` | `void createProblemsPanel();` | **NO** (`updateProblemsPanel` exists; Qt has different API) |
| `addProblem` overload drift | See below | Header has **different** arity/types |

**Header today (~L2944):**
```cpp
void addProblem(const std::string& file, int line, int col, const std::string& msg, int severity);
```

**ProblemsPanel.cpp defines:**
```cpp
void Win32IDE::addProblem(const std::string& file, int line, const std::string& message, OutputSeverity severity);
```

Suggested sole-builder options (pick one; do not invent both blindly):
1. Add overload matching the `.cpp`, keep existing 5-arg for `addProblemPublic`.
2. Or change `.cpp` to match header (`col` + `int severity`) — **signature align**, not dual semantics.

Also uses: `m_hwndProblemsPanel`, `m_hwndMain`, `m_hInstance`, `appendToOutput`/`OutputSeverity` (already declared), `ListView_*` (needs `commctrl.h` + init — include/macro, not Win32IDE member).

### B3. Annotation overlay TU — mostly cascade; small verify items

| Symbol | Plan |
|--------|------|
| `m_annotationOverlay`, overlay methods, `OutputSeverity`, `appendToOutput` | **Already declared.** C2027/`undefined type Win32IDE` in `Win32IDE_AnnotationOverlay.cpp` ⇒ ensure `#include "Win32IDE.h"` completes before method defs; do not redeclare members. |
| Log: `AnnotationOverlay.cpp` `m_agentBridgeReady` “not member of Win32IDE” | Member is on `RawrXD::UI::AnnotationOverlay` (`AnnotationOverlay.h` ~L145). Current `.cpp` returns `m_agentBridgeReady` inside overlay method — treat log as cascade/mis-attr unless repro. |
| Log: `AnnotationItem::rect` | Header field is `screenRect` (~L49). Current `.cpp` uses `item.screenRect`. If log still fires, rename remaining `.rect` → `.screenRect` in overlay `.cpp` (not a Win32IDE.h member add). |

### B4. Terminal tabs — mostly non-member / cascade

| Symbol | Plan |
|--------|------|
| `IDC_TERMTAB_FIRST` | **Already `#define` in header.** If undeclared, Win32IDE.h not visible / early parse fail. |
| `TerminalReaderThread` | File-local `static DWORD WINAPI TerminalReaderThread(LPVOID)` — forward-decl at top of `Win32IDE_TerminalTabs.cpp`. Not a Win32IDE member. |
| `CHARRANGE` / `CHARRANGEA` | Richedit type; ensure `<richedit.h>` + RichEdit load path. Not a class member. |
| `m_terminalTabs` | **Already declared.** C2597 illegal non-static ref ⇒ method not compiled as instance member (cascade from earlier error). |

### B5. Memory view — **source typo**, not missing Win32IDE member

`Win32IDE_MemoryView.cpp` L30 currently:

```cpp
namespace Raw rXD {
```

That space produces C2061 `rXD` and cascades all `RawrXD::IDE::g_memoryViewer` / `g_viewerMutex` / `MemoryViewer` errors.  
**Plan:** fix to `namespace RawrXD {` (TU-local). No `Win32IDE.h` decl required for these file-static symbols.

---

## C. Secondary C2039 methods (rebuild_b17_02.log) — after P01

Declare only if sole builder keeps those TUs linked; else document CMake exclude (per ERROR_FREQ optional-panel rule). Suggested stubs from def sites:

| TU | Missing method(s) | Suggested signature sketch |
|----|-------------------|----------------------------|
| `Win32IDE_Project.cpp` | `addWorkspaceRoot`, `removeWorkspaceRoot`, `listWorkspaceRoots` | `void addWorkspaceRoot(const std::string&);` / `void removeWorkspaceRoot(...);` / `std::vector<std::string> listWorkspaceRoots() const;` — **confirm from .cpp** |
| `Win32IDE_CompilerPanel.cpp` | `ShowCompilerOutput`, `navigateToError` | match `.cpp` defs |
| `Win32IDE_Git.cpp` | `gitStage`, `gitBranch`, `gitStash`, `gitCherryPick`, `gitStatus` | match `.cpp` |
| `Win32IDE_MonacoThemes.cpp` | `loadMonacoThemes` | `void loadMonacoThemes();` |
| `Win32IDE_ShortcutEditor.cpp` | `showShortcutEditor` | `void showShortcutEditor();` |
| `Win32IDE_StatusBarActions.cpp` | `initStatusBar`, `updateStatusBar` | may collide with existing status-bar APIs — **grep before add** |
| `Win32IDE_SettingsGUI.cpp` | `showSettingsGUI` | vs existing `showSettingsDialog` |
| `Win32IDE_CallStackSymbols.cpp` | `cmdCallStackCapture/ShowDialog/Copy/Resolve` | `void cmdCallStack…();` |
| `Win32IDE_DebugWatchFormat.cpp` | `cmdDbgWatchShow/Add/Format*/Clear` | `void cmdDbgWatch…();` |
| `Win32IDE_DAPServer.cpp` | `evaluateWatchExpression` | match `.cpp` |

These are **out of ERROR_FREQ top family**; do not block P01 member landing.

---

## D. Suggested minimal Win32IDE.h patch set (for sole builder)

Near theme / settings private section (after `m_appearance` / theme members):

```cpp
void initThemes();
void applyTheme(const std::string& themeName); // overload; keep void applyTheme();
```

Near problems panel section (beside `m_hwndProblemsPanel` / `updateProblemsPanel`):

```cpp
void createProblemsPanel();
// Optional overload if keeping ProblemsPanel.cpp signature:
void addProblem(const std::string& file, int line, const std::string& message, OutputSeverity severity);
```

**Do not add again:** `OutputSeverity`, `appendToOutput`, `m_settings`, `AppearanceSettings`, `m_appearance`, `m_annotationOverlay`, overlay init APIs, `m_hwndProblemsPanel`, `IDC_TERMTAB_FIRST`.

---

## E. Fail-closed disposition

```
PLAN_ONLY=1
SOURCE_EDIT_BY_ASSIST=0
CMAKE_EDIT_BY_ASSIST=0
BUILD_RUN_BY_ASSIST=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NOT_RUN != PASS
```

This file + `MEMBER_DECL_PLAN.json` are a **builder checklist**, not certification evidence.
