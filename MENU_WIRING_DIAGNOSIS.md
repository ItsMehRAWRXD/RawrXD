# Menu & Feature Wiring Diagnosis

## Executive Summary

Investigation of why menu items appear disconnected from features (GitHub chat, AI chat panel, file explorer, agent chat for autonomous use, breadcrumbs) reveals several root causes:

1. **delegateToGui infinite re-entry** — Handlers that use `delegateToGui(ctx, id, ...)` PostMessage the same WM_COMMAND ID back to the main window. Since `onCommand` only calls `routeCommandUnified` (never `routeCommand`), the same handler runs again → infinite loop. This affects: Breadcrumbs (12020), Module Browser (2022), Git Panel (3024), Theme Editor, and other View/UI commands.
2. **routeCommand never invoked** — `routeCommand()` in Win32IDE_Commands.cpp contains the actual implementations (e.g. `handleViewCommand` → `showModuleBrowser`, `handleTier1Command` → breadcrumbs toggle), but `onCommand` in Win32IDE_Core.cpp **never calls** `routeCommand`. It only calls `routeCommandUnified`. So the real handlers in routeCommand/handleViewCommand/handleTier1Command are never reached.
3. **File Explorer & Chat access** — The Activity Bar (Files, Chat buttons) and View > AI Chat are wired, but the secondary sidebar (AI Chat) and primary sidebar (File Explorer) may not be visible or may have placeholder content.
4. **Agent Chat / Agentic use** — There is no dedicated “Agent Chat” panel for autonomous/agentic workflows; the AI Chat panel is generic. Agent commands (Start Agent Loop, Bounded Agent) go through COMMAND_TABLE but may not surface a usable chat UI for agentic interaction.

---

## Detailed Findings

### 1. delegateToGui Pattern Creates Infinite Re-Entry

**Location:** `src/core/ssot_handlers.cpp` line 37–41

```cpp
static CommandResult delegateToGui(const CommandContext& ctx, uint32_t cmdId, const char* name) {
    if (ctx.isGui && ctx.idePtr) {
        HWND hwnd = *reinterpret_cast<HWND*>(ctx.idePtr);
        PostMessageA(hwnd, WM_COMMAND, cmdId, 0);   // ← Posts SAME cmdId
        return CommandResult::ok(name);
    }
    ...
}
```

When a user clicks e.g. **View > Breadcrumbs** (ID 12020):

1. `onCommand(12020)` → `routeCommandUnified(12020)` → `handleTier1BreadcrumbsToggle(ctx)`
2. `handleTier1BreadcrumbsToggle` calls `delegateToGui(ctx, 12020, ...)`
3. `delegateToGui` does `PostMessage(hwnd, WM_COMMAND, 12020, 0)`
4. Message loop later delivers WM_COMMAND 12020 again → back to step 1 → infinite loop

**Affected commands (via delegateToGui):**

- `handleTier1BreadcrumbsToggle` (12020) — View > Breadcrumbs
- `handleViewModuleBrowser` (2022) — View > Module Browser
- `handleGitDiff` (3024) — Git > Git Panel
- `handleViewThemeEditor` (2023), `handleViewFloatingPanel` (2024), etc.
- Many other View/Theme/Transparency handlers

---

### 2. routeCommand Never Called from onCommand

**Location:** `src/win32app/Win32IDE_Core.cpp` (onCommand), `src/win32app/Win32IDE_Commands.cpp` (routeCommand)

Flow in `onCommand`:

1. Switch handles a few IDs directly: 2001–2005, 1030–1035, 2026, 2027, 502, 1024, 1106, 1022, 3007
2. Calls `routeCommandUnified(id, this)` — **never** `routeCommand(id)`
3. If `routeCommandUnified` returns true, returns; otherwise shows “Unknown command”

The real logic lives in:

- `routeCommand()` → `handleViewCommand()` → `showModuleBrowser()`, `toggleSecondarySidebar()`, etc.
- `routeCommand()` → `handleTier1Command()` → breadcrumbs, minimap, fuzzy palette, etc.
- `routeCommand()` → `handleGitCommand()` → Git Panel

But `routeCommand` is **never called** from `onCommand`. So these implementations are unreachable for menu-driven commands.

---

### 3. ID Mismatches and Hardcoded Values

| Menu Item           | Win32IDE.cpp Menu ID | COMMAND_TABLE ID | Notes                                       |
|---------------------|----------------------|------------------|---------------------------------------------|
| View > AI Chat      | 3007 (hardcoded)     | —                | Handled in switch (3007) → works            |
| View > Breadcrumbs  | IDM_T1_BREADCRUMBS_TOGGLE (12020) | 12020  | delegateToGui → infinite loop               |
| View > Module Browser | IDM_VIEW_MODULE_BROWSER (2022) | 2022 | delegateToGui → infinite loop               |
| Git > Git Panel     | IDM_GIT_PANEL (3024) | 3024 (handler: handleGitDiff) | delegateToGui → infinite loop   |
| GH button (title bar) | IDC_BTN_GITHUB 1022 | —                | Handled in switch (1022) → works            |

---

### 4. File Explorer

**Status:** Wired at the plumbing level.

- Activity Bar “Files” button (IDC_ACTIVITY_EXPLORER 6001) → `setSidebarView(SidebarView::Explorer)`
- `createPrimarySidebar` → `createExplorerView` → `m_hwndExplorerTree`
- Sidebar visible by default (`m_sidebarVisible = true`)

**Possible gaps:**

- Sidebar may be collapsed or not shown depending on startup layout.
- Explorer tree population may be incomplete (e.g. working directory, refresh).
- Ctrl+B / View > Sidebar toggle may not be obvious.

---

### 5. AI Chat Panel (Secondary Sidebar)

**Status:** Toggle is wired.

- View > AI Chat (3007), Ctrl+Alt+B
- Activity Bar “Chat” button (IDC_ACTIVITY_CHAT 6007) → `toggleSecondarySidebar()`
- Title bar “GH” button (1022) → `toggleSecondarySidebar()`

**Known issues (MENU_FEATURE_WIRING_AUDIT.md):**

- Send/Clear buttons needed subclassing so WM_COMMAND reaches main window.
- Labels changed from “GitHub Copilot Chat” to “AI Chat”.

**Possible gaps:**

- Chat may show placeholder responses (“Load a model to start chatting”, “Inference not wired”).
- No explicit “Agent Chat” for autonomous/agentic workflows; same panel used for generic AI chat.

---

### 6. Agent Chat for Autonomous/Agentic Use

**Status:** No dedicated Agent Chat UI.

- Agent menu: Start Agent Loop, Bounded Agent (FIM Tools), Execute Command, View Tools, View Status.
- These go through COMMAND_TABLE (handleAgentLoop, handleAgentBoundedLoop, etc.).
- Output appears in Output panel / status bar, not in a dedicated agent chat.
- The AI Chat (secondary sidebar) is generic chat; there is no separate panel for agent tool calls, plan steps, or autonomous execution.

---

## Recommended Fixes

### A. Fix delegateToGui → Direct IDE Call

For GUI-originated commands, handlers should call the IDE directly instead of re-posting WM_COMMAND:

```cpp
// In handleTier1BreadcrumbsToggle, handleViewModuleBrowser, handleGitDiff, etc.:
if (ctx.isGui && ctx.idePtr) {
    Win32IDE* ide = reinterpret_cast<Win32IDE*>(ctx.idePtr);
    ide->handleTier1Command(12020);  // or showModuleBrowser(), etc.
    return CommandResult::ok("tier1.breadcrumbs");
}
```

This avoids infinite re-entry and uses the real implementations in routeCommand/handleViewCommand/handleTier1Command.

### B. Route Unhandled COMMAND_TABLE IDs to routeCommand

Alternative: after `routeCommandUnified` runs a delegateToGui-style handler, have the handler **not** PostMessage. Instead, extend `onCommand` to fall back to `routeCommand` when the unified handler returns “delegate to IDE”:

```cpp
// In onCommand, after routeCommandUnified returns:
if (!handled && routeCommand(id)) return;  // Fallback to legacy routeCommand
```

This would allow existing routeCommand logic to execute for IDs that currently only delegate.

### C. Add Agent Chat Surface

- Add a dedicated Agent panel or tab that shows:
  - Agent tool calls, plan steps, and status
  - Autonomous execution log
- Wire Agent menu items to open/focus this panel.
- Optionally split “AI Chat” (general) vs “Agent Chat” (agentic workflow) if UX requires it.

### D. Improve File Explorer Discoverability

- Ensure sidebar is visible and Explorer view is default on first run.
- Add View > File Explorer menu item that calls `setSidebarView(SidebarView::Explorer)` and shows the sidebar.
- Verify Explorer tree populates for the working directory and refreshes correctly.

---

## Files to Modify

| File                          | Change                                                                 |
|-------------------------------|------------------------------------------------------------------------|
| `src/core/ssot_handlers.cpp`  | Replace delegateToGui with direct Win32IDE calls where appropriate    |
| `src/win32app/Win32IDE_Core.cpp` | Optionally add routeCommand fallback for unhandled GUI commands    |
| `src/win32app/Win32IDE.cpp`   | Add View > File Explorer if missing                                  |
| New or existing Agent UI      | Add Agent Chat / Agent panel for autonomous workflows                 |

---

## Updates (2026-02-13)

- **Git menu (3020–3024)** — Added cases to `handleViewCommand` in Win32IDE_Commands.cpp; Git Status, Commit, Push, Pull, Git Panel now wired.
- **View > Agent Chat** — Added menu item (same as AI Chat, ID 3007) for agentic discoverability.
- **VSIX extraction** — PowerShell Expand-Archive used first (most reliable for .vsix ZIP on Windows).
- **Extensions panel** — "Install .vsix..." button added; installs to %APPDATA%\RawrXD\extensions.
- **VSIX_TEST_GUIDE.md** — Guide for Amazon Q and GitHub Copilot; `scripts/Test-VSIXInstall.ps1` for agentic testing.

## References

- `MENU_FEATURE_WIRING_AUDIT.md` — Prior fixes for Chat Send/Clear, Activity Bar
- `HANDLER_AUDIT_REPORT.md` — COMMAND_TABLE and delegateToGui handler inventory
- `docs/WIN32_IDE_WIRING_MANIFEST.md` — Wiring manifest
- `src/core/command_registry.hpp` — COMMAND_TABLE
- `src/win32app/Win32IDE_Commands.cpp` — routeCommand, handleViewCommand, handleTier1Command
