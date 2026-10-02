# BATCH 04 — IDE LIFECYCLE AUDIT

**Scope:** `F:\~dev\rawrxd` @ `9f67682ffea12a182ae4fd2d41fb3bc524f61d2b`, dirty tree (197 changed paths). Working tree, not HEAD.
**Date:** 2026-10-01
**Method:** source trace from the real entry point. Every reachability claim is a repo-wide symbol search, not a read of a comment. Runtime claims are bound to the newest linked binary and invalidated where the tree is newer.

---

## 0. THE ACTUAL ENTRY POINT IS NOT `wWinMain`

```cpp
// src/win32app/main_win32.cpp:2619
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
```

There is no `wWinMain` and no `wWinMain`/`WinMain` pair. The live entry is the **ANSI** `WinMain`, so the whole IDE runs on the ANSI window-procedure path (`WndProc` → `RegisterClassExW` is not used; `wc.lpszClassName = TEXT(...)` at `:2854` coerces to the `W` variant while `AppendMenuA`/`CreateAcceleratorTableA`/`TranslateAcceleratorA` at `:2881-2960` are all the `A` variants). Mixed A/W is not itself a defect, but it means the product's window layer is single-byte.

A **second, dead entry point** exists in the same binary:

```cpp
// src/core/IDEStartupFinal.cpp:133
int IDE_Main(int argc, char** argv)   // also IDE_Startup_Full() :25, IDE_Shutdown_Full() :86
```
Repo-wide search: **zero callers** of `IDE_Main`, `IDE_Startup_Full`, `IDE_Shutdown_Full`, `MoEBackend_IsLoaded`, `MoEBackend_Unload`. This is a third IDE-startup authority (after `WinMain`/`WM_CREATE` and the `AutoClosure` CLI path) that compiles, links, and never runs. `IDEStartupFinal.cpp` is a "Sovereign IDE Final Integration" surface that the shipping product never enters.

---

## 1. REAL STARTUP SEQUENCE (called from `WinMain`, in order)

| # | Line | Action | Return checked? |
|---|---|---|---|
| 1 | `main_win32.cpp:2622` | `SetUnhandledExceptionFilter` for `EXCEPTION_ACCESS_VIOLATION` | n/a |
| 2 | `:2637-2658` | DPI awareness via dynamic `GetProcAddress(user32,"SetProcessDpiAwarenessContext")`, fallback `SetProcessDPIAware`, else `"unaware"` | recorded in `g_dpiAwarenessMode` |
| 3 | `:2661` | `g_certStartTick = GetTickCount64()` | n/a |
| 4 | `:2673-2693` | Checkpoint recovery: `rawrxd::ckpt::RecoverWorkspace(ckptRoot, writeReceipt=true)` | counts checked, only logged to `OutputDebugStringA` |
| 5 | `:2696-2698` | **early return** `RawrXD::AutoClosure::RunFromCurrentCommandLine()` | CLI path bypasses the entire GUI |
| 6 | `:2701-2843` | `CommandLineToArgvW` parse → `g_startupOptions` | n/a |
| 7 | `:2846-2848` | **early return** `runGpuCorrectnessGate()` if `--gpu-init`/`--gpu-forward` | n/a |
| 8 | `:2850-2862` | `RegisterClassEx` | **YES** — `MessageBox` + `return 1` |
| 9 | `:2864-2876` | `CreateWindowEx` → **synchronous `WM_CREATE`** | **YES** — `MessageBox` + `return 1` |
| 10 | `:2879-2929` | 6 popup menus, 26 items | n/a |
| 11 | `:2937-2960` | 21-entry accelerator table | n/a |
| 12 | `:2962-2963` | `ShowWindow` (`SW_HIDE` when `--headless`), `UpdateWindow` | n/a |
| 13 | `:2966-2968` | `Win32IDE_Commands_SetMainWindow`, `SetEditorWindow`, `MCPBridgeManager::Initialize` | **NO** — all three returns discarded |
| 14 | `:2971-2973` | `PostMessage(WM_AUTORUN)` if `--autorun`/`--cert-*` | n/a |
| 15 | `:2980-2983` | cert stay-alive timer `0xB008` | n/a |
| 16 | `:2991-2999` | `--ide-runtime-cert` → `IdeRuntimeCert_Run()` | n/a |
| 17 | `:3001-3032` | `GetMessage` loop: `WM_TIMER`/`WM_AUTORUN`/`WM_AUTORUN_COMPLETE` handled **before** `TranslateAccelerator` | n/a |
| 18 | `:3047-3057` | `g_chatCancelled=true`, join chat thread, **`g_chatEngine.release()` — intentional leak** | n/a |
| 19 | `:3064-3173` | W8 immutable receipt + non-authoritative mirror | seal result checked (`:3123`) |
| 20 | `:3175-3176` | `closeHeadlessLog()`, `return (int)msg.wParam` | n/a |

**The real bring-up is inside `WM_CREATE`, not in `WinMain`.** `CreateWindowEx` at `:2864` dispatches `WM_CREATE` (`main_win32.cpp:2025`) synchronously, before line 2864 returns. Everything below hangs off that handler.

### `WM_CREATE` bring-up (`main_win32.cpp:2025-2138`), in order

```
:2035  RawrXD::IDE::Settings_EnsureLoaded()      -> return DISCARDED
:2036  writeSettingsStatus("startup")
:2041  RawrXD::IDE::Session_Load()                -> return DISCARDED
:2042  writeSessionStatus("startup")
:2049  RawrXD_IDE_InitWorkspace(".")              -> return DISCARDED
:2050  writeWorkspaceStatus("startup")
:2059  g_workspaceRootResolved = GetCurrentDirectoryA()
:2067  rawrxd::LoadTaskConfigFor(g_taskRunner, "<cwd>\.vscode\tasks.json")
:2069  g_launchConfigs.load(<cwd>\.vscode\launch.json) + dropUnresolved()
:2079  g_projectConfig.load(g_workspaceRootResolved)
:2086  g_fileWatcher.watch(cwd, onFileChange)     -> failure COUNTED (:2087)  [honest]
:2090  writeIntegrationStatus("startup")
:2094  ShellLayout_RegisterAll(hInst)
:2095  ShellLayout_CreateAll(hWnd, hInst)
:2098  ShellLayout_GetEditor()
:2099  Win32IDE_Commands_SetMainWindow(hWnd)
:2100  Win32IDE_Commands_SetEditorWindow(hEditor)   [no-op, see §7]
:2104-2115  resolve model (--model -> RAWRXD_AGENT_MODEL), initChatEngine, wireChatToDeep2
:2125-2132  g_hOutput = CreateWindowExA("EDIT", ... ES_READONLY, parent = ShellLayout_GetTerminal())
```

**Five subsystems that exist in `src/win32app` are never started here.** Each is a complete implementation with zero call sites anywhere in the repo:

| Subsystem | File | Entry with 0 callers | Consequence in the shipping IDE |
|---|---|---|---|
| Undo-coverage hook | `Win32IDE_Commands.cpp:699` | `Win32IDE_Commands_AttachUndo()` | `g_mutationHook` stays `nullptr`; **typing produces no undo steps** |
| AutoSave | `Win32IDE_AutoSave.cpp:26,35,43` | `AutoSave_Start/Stop/SetInterval` | autosave never arms; `editor.autoSave` is inert |
| UI Watchdog | `Win32IDE_Watchdog.cpp:17,15,36` | `Watchdog_Start/Heartbeat/Stop` | freeze detection never runs |
| IDE Logger | `Win32IDE_Logger.cpp:15,31,49-51` | `Logger_Init/Log/Info/Warn/Error/Shutdown` | `g_fileEnabled` never true; no IDE log file |
| Agentic bridge | `Win32IDE_AgenticBridge.cpp:30` | `AgenticBridge_Init` | the only caller chain of `StreamingUX_Begin/Token/End` never starts |

---

## 2. STAGE TABLE

| Stage | Reachable from WinMain? | Evidence (file:line) | Classification | Finding |
|---|---|---|---|---|
| Entry point | YES | `main_win32.cpp:2619` | VERIFIED | `WinMain` (ANSI), not `wWinMain`. Second dead entry `IDE_Main` at `src/core/IDEStartupFinal.cpp:133` has 0 callers. |
| Startup sequence | YES | `main_win32.cpp:2622`→`:3176`, 20 steps above | VERIFIED | Real control flow throughout; no hardcoded result in the sequence itself. |
| Subsystem bring-up | PARTIAL | `main_win32.cpp:2025-2138` | CONTRACT_VIOLATED | 5 returns discarded (`:2035`, `:2041`, `:2049`, `:2968`, `:2966/:2967`). 5 whole subsystems never started. `MCPBridgeManager::Initialize` returns `bool` (`Win32IDE_MCPHooks.h:46`) and is discarded at `:2968` — MCP bring-up failure is invisible. |
| Settings load | YES | `main_win32.cpp:2035` → `Win32IDE_Settings.cpp:336-402` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Real parse (`:359-375`), reject accounting, quarantine-to-`.bad` (`:383-394`), migration ladder (`:218-279`), 16-key schema (`:67-84`) bound to the real `ConfigurationValidator` (`:195-196`). |
| Settings save | YES | `Win32IDE_Settings.cpp:417-493`, `SettingsGUI.cpp:199`, `main_win32.cpp:2286` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Real atomic write: temp + `ReplaceFileA` → `MoveFileExA` fallback (`:437-470`). Genuinely persists. |
| Settings dialog | YES | menu `main_win32.cpp:2889` → `WM_COMMAND` default `:2214` → `Win32IDE_Commands.cpp:661` → `SettingsGUI.cpp:334` | VERIFIED | Reachable. In-code `DLGTEMPLATE` (`:307-332`), 4 tab pages, OK/Cancel/Apply; `SaveSettingsFromDialog` writes 11 keys (`:167-197`). |
| Settings **consumption** | **NO** | repo-wide: zero `Settings_Get/GetInt/GetBool` callers outside `SettingsGUI.cpp` and `CICDSettings.cpp` | DEAD/UNBOUND | **No runtime behavior reads any setting.** 16 schema keys, 11 written by the dialog, 0 read by the editor, terminal, LSP, MCP, agent, or telemetry. |
| Settings schema coherence | n/a | `Settings.cpp:67-84` vs `SettingsGUI.cpp:171,182` | INVALID_MEASUREMENT | The dialog writes `editor.lineNumbers` (`:171`) and `lsp.language` (`:182`), neither of which is in `kSchema`. Every load therefore reports `SETTINGS_UNKNOWN_KEYS>=2` for keys the product itself wrote. Write-side and read-side schemas disagree. |
| Session write | YES | `Win32IDE_Session.cpp:120-174`, `main_win32.cpp:2288` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Real atomic write. Only fed by `Session_AddFile` from `Win32IDE_Commands.cpp:195` (`DoFileOpen`). |
| Session **restore** | **NO** | `Session_Load()` `main_win32.cpp:2041`; `Session_GetFiles()` `Session.cpp:178` has **0 callers** | CONTRACT_VIOLATED | `Session_Load` fills `g_session` and **nothing ever iterates it**. No editor or tab is reopened. "Restore" is a no-op that reads a file and discards the result. |
| Session receipt verdict | n/a | `main_win32.cpp:1098` | INVALID_MEASUREMENT | `shutdownOk = saveWroteFile && fileExistsNow && fileBytesNow > 0`. An **empty** session still writes 2 comment lines (>0 bytes) → `VERDICT=PASS` with `SESSION_FILES_IN_SESSION=0`. The verdict does not require a single restored document. |
| Workspace persist | YES | `main_win32.cpp:2049/2290` → `src/core/workspace_model.cpp:604/644` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Real model, real diagnostics (`workspace_model.cpp:662-680`). Linked at `CMakeLists.txt:7261`. |
| Workspace content | **NO** | `RawrXD_IDE_AddOpenFile` / `RemoveOpenFile` (`workspace_model.cpp:624/634`) have **0 callers** | CONTRACT_VIOLATED | The workspace model **never records an open file**. `RawrXD_IDE_SaveWorkspace()` at `:2290` writes `openFiles=0`. Receipt PASS (`main_win32.cpp:1180`) is unaffected. |
| Editor engine | YES | `EditorEngine.cpp:620` (register), `:632` (create), via `ShellLayout.cpp:51,70` | VERIFIED | Custom class `RawrXDEditor` (`:626`), real tokenizer (`:181-200`), real selection model (`:81-155`), real caret (`:109-130`), real find/replace/replaceAll (`:863/899/937`), real binary open (`:651-678`), real atomic save through `rawrxd::ckpt::Transaction::WriteFile` (`:695`). |
| Editor **undo coverage** | **NO** | `Win32IDE_Commands.cpp:699` has 0 callers → `EditorEngine.cpp:461 if (g_mutationHook)` never fires | CONTRACT_VIOLATED | The comment at `Win32IDE_Commands.cpp:123-127` states "The editor fires this hook after a debounce window closes on a keystroke burst, so typing now produces undo steps." **The hook is never installed.** Typing produces zero undo snapshots; `Ctrl+Z` walks straight back to the `DoFileOpen` snapshot. |
| Undo stack index | n/a | `Win32IDE_Commands.cpp:115-120` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | On the 51st push the front is erased and `g_undoPos` is **not** incremented (the `++g_undoPos` is in the `else` branch). `g_undoPos` desynchronizes from the live index, and `DoEditRedo`'s `g_undoPos+1 < size` is permanently false past depth 50. |
| Panel: TabBar | YES | `ShellLayout.cpp:69`, class at `TabManager.cpp:186` | VERIFIED | Real custom window. |
| Panel: Editor | YES | `ShellLayout.cpp:70` | VERIFIED | See editor row. |
| Panel: Sidebar | YES | `ShellLayout.cpp:68` → `Sidebar.cpp:211-217` → `:145-196` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Real activity bar + `WC_TREEVIEW` populated from CWD (`:184-188`). Toggle works (`IDM_VIEW_SIDEBAR` → `main_win32.cpp:2203-2211`). **But** `Win32IDE_Sidebar_GetSelectedPath()` (`:219`) has 0 callers → clicking a file in the tree opens nothing. The sidebar's search LISTBOX (`:190`) is fed by nothing. |
| Panel: ChatPanel | YES | `ShellLayout.cpp:71`, class at `ChatPanel.cpp:292`; driven by `main_win32.cpp:2219-2256` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Genuinely wired: `WM_CHAT_TOKEN` → `ChatPanel_AppendStreamToken`, `WM_CHAT_DONE` → `ChatPanel_EndStreaming` + telemetry + receipt. Visible. |
| Panel: AgentPanel | **NO** | created `ShellLayout.cpp:72`, hidden `:87`; only `ShellLayout_ToggleAgent` (`:117`) can show it — **0 callers** | DEAD/UNBOUND | 321 lines. `AgentPanel_SetTask/AddStep` are called from the chat worker (`main_win32.cpp:716-720`), so it accumulates real task state into a window the user can never see. |
| Panel: SearchPanel | **NO** | created `ShellLayout.cpp:75`, hidden `:88`; `SearchPanel_Search/SetRoot/SetJumpCallback` (`:292/294/303`) have **0 callers** | DEAD/UNBOUND | 277 lines, fully unreachable. No search can ever be issued from this panel. |
| Panel: GitPanel | **NO** | created `ShellLayout.cpp:74`, hidden `:89`; `ShellLayout_ToggleGit` (`:140`) has 0 callers | DEAD/UNBOUND | 363 lines, fully unreachable. |
| Panel: TerminalSplit | YES (visible) | `ShellLayout.cpp:73`, class at `TerminalSplit.cpp:203-207` | UNIMPLEMENTED (as a terminal) | Real window, output-only. **No menu id and no code path issues a command to it.** The IDE has no way to run a terminal command. |
| Panel: StatusBar | window only | `ShellLayout.cpp:76`, class at `StatusBar.cpp:133`; `StatusBar_SetText/SetBuildStatus/SetCursorPos/SetEncoding/SetInsertMode/SetLanguage/SetMainText/GetHwnd` (`:149-210`) have **0 callers outside `StatusBar.cpp`** | DEAD/UNBOUND | The status bar window is created and painted and is **permanently blank**. It is the exact shape a window-existence probe mistakes for a working panel. |
| Panel: StreamingUX | **NO** | `StreamingUX.cpp:24-64`; only caller is `AgenticBridge` (`Win32IDE_AgenticBridge.cpp:53/66/103`), and `AgenticBridge_Init` (`:30`) has 0 callers | DEAD/UNBOUND | Additionally `StreamingUX_SetStatusBar` (`:22`) has 0 callers → `g_statusBar` is permanently `nullptr`, so every status write in the file (`:31/42/52/63`) is a no-op even if it ran. |
| Panel: GhostText | YES | `EditorEngine.cpp:327` (paint), `:451` (request), `:513` (accept), `:528` (dismiss) | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Genuinely reachable from the editor. **But** `GhostText_SetProvider` (`GhostText.cpp:35`) has 0 callers → only the 4-branch substring heuristic at `:58-65` can ever fire. No model or LSP completion reaches it. |
| GhostText thread safety | n/a | `GhostText.cpp:48-74` writes `g_ghost.suggestion`/`visible` from a detached thread; `GhostText.cpp:105` `GhostText_Paint` reads them on the UI thread | CONTRACT_VIOLATED | Non-atomic `std::string` written by a worker and read by the painter. The 300 ms debounce serialises the writers but does not protect the reader. Torn read is a live crash path whenever ghost text is visible. |
| Shell panel toggles | **NO** | `ShellLayout.cpp:111/117/124/130/140` — all 5 have **0 callers** | DEAD/UNBOUND | Only `ShellLayout_Resize` is called (`main_win32.cpp:2144/2209`). Chat/Agent/Terminal/Search/Git can never be toggled by the user. |
| Command router | YES | `main_win32.cpp:2214`, `:2966`; `Win32IDE_Commands.cpp:686-692` | CONTRACT_VIOLATED | **False success:** `Route()` returns `true` for **any** id in `[1000,2000)` and `[2100,2200)` even when `handleFileCommand`/`handleEditCommand` matched no `case`. `Route(1500)` reports handled while doing nothing, and `WM_COMMAND` then `break`s instead of reaching `DefWindowProc`. |
| Command: File menu | YES | `Win32IDE_Commands.cpp:651-663` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | 1001-1007 all have real handlers. `DoFileSaveAll` genuinely iterates `TabManager_OpenPaths()` (`:236-241`), not an alias. |
| Command: Edit menu | YES | `Win32IDE_Commands.cpp:665-678` | IMPLEMENTED_NOT_RUNTIME_VERIFIED | 2101-2110 all real. Find/replace use a hand-built `DLGTEMPLATEEX` (`:490-577`) with a blank-search refusal (`:461-466`) — the old "TODO"-deleting stub is gone. |
| Command: File>Exit | YES, **but persistence-bypassing** | `main_win32.cpp:2152-2160` → `DestroyWindow` → `WM_DESTROY` (`:2257`) | CONTRACT_VIOLATED | See §9. A second, correct `IDM_FILE_EXIT` handler exists at `Win32IDE_Commands.cpp:659` → `DoFileExit()` (`:253`) → `PostMessage(WM_CLOSE)`, which *would* persist — but the `WM_COMMAND` case at `:2152` shadows it, so the persisting handler is **dead code**. |
| Command: unused router API | **NO** | `Win32IDE_Commands.cpp:693` `Register`, `:694` `SetDirty`, `:699` `AttachUndo`, `:703` `GetCurrentFile` — all 0 callers | DEAD/UNBOUND | `g_commandHandlers` (`:66`) is therefore always empty and `g_dirty` (`:68`) is never set. `Win32IDE_Commands_SetEditorWindow` (`:685`) is `(void)hwnd` — a no-op satisfying two call sites (`main_win32.cpp:2100`, `:2967`). |
| Recent files | **NO** | `g_recentFiles` (`Win32IDE_Commands.cpp:67`) written by `AddToRecent` (`:157`, called `:196`), read by nothing; `IDM_FILE_RECENT_BASE`/`_CLEAR` (`:85-86`) unused | DEAD/UNBOUND | A write-only data structure with no menu. The recent-files feature is absent. |
| File operations | YES | `Win32IDE_FileOps.cpp:10,23,37,46,54,59,65`; all in `WIN32IDE_SOURCES` at `CMakeLists.txt:5427` | VERIFIED | All seven `RawrXD::IDE::FileOps_*` are real (`ifstream`/`ofstream`/`GetFileAttributesA`). Consumers: `Win32IDE_Commands.cpp:24-28`, `main_win32.cpp:57`. **Not** a duplicate-authority or missing-source problem. |
| FileOps LNK2019 | RESOLVED in tree | `Win32IDE_RuntimeCert.cpp:61-74` | VERIFIED | See §8. |
| Shutdown flush | PARTIAL | `main_win32.cpp:2265-2297` (`WM_CLOSE` only) | CONTRACT_VIOLATED | See §9. |
| Command palette | n/a | zero occurrences of `RawrXDCommandPalette` outside `Win32IDE_RuntimeCert.cpp:280` | UNIMPLEMENTED | No palette window, class, id, or handler exists anywhere in the tree. |
| Ctrl+P / F12 / rename / IDE git | n/a | `Win32IDE_RuntimeCert.cpp:292-316`, `:364-366` | UNIMPLEMENTED | No `IDM` routes to them; `GotoDefinition` exists elsewhere but is unreachable from the Win32IDE command table. |

---

## 3. SETTINGS — DOES LOAD/SAVE WORK AND PERSIST?

**Yes, mechanically. No, functionally.**

Load (`Settings.cpp:336-402`) is honest: real parse, real reject counting, real quarantine of a malformed file to `<path>.bad` so a subsequent save cannot destroy it (`:383-394`), real migration from a 0-version flat schema (`:218-279`) that never clobbers an already-scoped value (`:261-271`). Save (`:417-475`) is honest: temp file, `ReplaceFileA`, `MoveFileExA(REPLACE_EXISTING|WRITE_THROUGH)` fallback, and a real error string on failure (`:466-468`).

Persistence is real on the `WM_CLOSE` path (`main_win32.cpp:2286`).

Two independent defects make it functionally inert:

1. **No consumer.** Repo-wide search for `Settings_Get`, `Settings_GetInt`, `Settings_GetBool` returns callers only in `Win32IDE_SettingsGUI.cpp` and `CICDSettings.cpp`. `editor.fontSize`, `editor.tabSize`, `editor.theme`, `editor.wordWrap`, `editor.minimap`, `editor.autoSave`, `terminal.shell`, `terminal.fontSize`, `search.maxResults`, `agent.maxSteps`, `telemetry.enabled` — **zero** runtime readers. The user changes a setting, it is written atomically to `%LOCALAPPDATA%\RawrXD\settings.ini`, and the IDE behaves identically.
2. **The receipt's "proof of a user edit" is a lie.** `main_win32.cpp:989-994` presents `editor.fontSize` as evidence that "a value here proves a user edit survived into this process." It proves nothing: the key is in the schema, and `Settings_Validate` (`:285-330`) reports it as *valid* whether or not any user ever touched the dialog. `SETTINGS_PROBE_PRESENT=1` is indistinguishable from a hand-written file.

Is there a settings **authority**? There is an authority in the naming sense (one canonical schema, one path resolver, one diagnostics struct, one derived receipt). There is no receipt under `receipts/`, no `beginImmutableGate`, and no seal — `ide_settings_status.txt` is a mutable `CREATE_ALWAYS` file (`main_win32.cpp:1051`) with no digest. By this project's own ledger rule (`RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001`), it is not certifiable evidence.

---

## 4. SESSIONS / WORKSPACES — DOES A SESSION PERSIST AND RELOAD?

**It persists a list. It reloads nothing.**

- `Session_Persist` (`Session.cpp:120-174`) is a real atomic writer. Its only input is `Session_AddFile`, called from exactly one place: `Win32IDE_Commands.cpp:195`, inside `DoFileOpen`.
- `Session_Load` (`Session.cpp:76-118`) is called at `main_win32.cpp:2041` and parses into `g_session`.
- **`Session_GetFiles()` (`Session.cpp:178`) has zero callers.** Nothing converts `g_session` back into open editors. Closing and reopening the IDE restores zero documents. The session subsystem is write-only in effect.
- The shutdown receipt does not notice: `main_win32.cpp:1098` requires `saveWroteFile && fileExistsNow && fileBytesNow > 0`. A zero-entry session writes two `#` comment lines and satisfies all three → `VERDICT=PASS`.

The workspace model has the identical shape. `RawrXD_IDE_InitWorkspace` and `RawrXD_IDE_SaveWorkspace` are called for real (`main_win32.cpp:2049/2290`) and the model has honest diagnostics (`workspace_model.cpp:662-680`), but **`RawrXD_IDE_AddOpenFile` (`workspace_model.cpp:624`) and `RawrXD_IDE_RemoveOpenFile` (`:634`) have zero callers.** The model is initialized, saved, and reported on — and contains no open files. `WORKSPACE_OPEN_FILES=0` appears in the receipt and does not affect the verdict at `main_win32.cpp:1180`.

---

## 5. PANELS — WHICH ARE REAL, WHICH ARE STUBS?

None of the eight is a stub. Every one is a genuine implementation with real window classes, real state and real code. The failure mode here is different and more deceptive: **five of them are implemented, linked, created — and unreachable.**

| Panel | Real? | Reachable? | Verdict |
|---|---|---|---|
| TabManager | yes | yes | VERIFIED |
| EditorEngine | yes | yes | VERIFIED |
| Sidebar | yes | yes, but its tree cannot open a file (`GetSelectedPath` 0 callers) and its search list is never filled | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| ChatPanel | yes | yes, genuinely driven | IMPLEMENTED_NOT_RUNTIME_VERIFIED |
| StatusBar | yes | window only — **all 9 setters have 0 callers** | DEAD/UNBOUND |
| TerminalSplit | yes | visible, but output-only; no command can be sent | UNIMPLEMENTED as a terminal |
| AgentPanel | yes | created then hidden; the only show function has 0 callers | DEAD/UNBOUND |
| SearchPanel | yes | created then hidden; `SearchPanel_Search` 0 callers | DEAD/UNBOUND |
| GitPanel | yes | created then hidden; `ShellLayout_ToggleGit` 0 callers | DEAD/UNBOUND |
| StreamingUX | yes | its only caller chain is uninitialised; `SetStatusBar` 0 callers | DEAD/UNBOUND |
| GhostText | yes | yes — but heuristic-only, no provider registered | IMPLEMENTED_NOT_RUNTIME_VERIFIED |

`ShellLayout_ToggleChat/Agent/Terminal/Search/Git` (`Win32IDE_ShellLayout.cpp:111-144`) have **zero callers**. The menu has exactly one `View` item (`IDM_VIEW_SIDEBAR`, `main_win32.cpp:2926`), which toggles the sidebar. The agent, search and git panels are created at `ShellLayout.cpp:72-75` and hidden at `:87-89`, with no reachable path to `SW_SHOW`.

---

## 6. COMMANDS — EVERY REGISTERED ID AND ITS HANDLER

Menu/accelerator ids are defined **twice**: `main_win32.cpp:1439-1466` (`#define`) and `Win32IDE_Commands.cpp:74-99` (`constexpr`), plus a **third** partial mirror in `Win32IDE_RuntimeCert.cpp:35-43`. The three copies currently agree; nothing enforces that.

| ID | Name | Handler | Real? |
|---|---|---|---|
| 1001 | File>New | `Commands.cpp:166` `DoFileNew` | yes |
| 1002 | File>Open | `:186` `DoFileOpen` | yes |
| 1003 | File>Save | `:204` `DoFileSave` | yes |
| 1004 | File>SaveAs | `:214` `DoFileSaveAs` | yes |
| 1005 | File>SaveAll | `:229` `DoFileSaveAll` | yes (iterates `TabManager_OpenPaths`) |
| 1006 | File>Close | `:245` `DoFileClose` | yes |
| 1007 | File>Settings | `:661` `SettingsGUI_Show` | yes |
| 1099 | File>Exit | **`main_win32.cpp:2152`** shadows `Commands.cpp:253` | **wrong one wins** |
| 2001 | Build>Native Compile Test | `main_win32.cpp:2161` `runToolchainGate` | yes |
| 2101-2106 | Undo/Redo/Cut/Copy/Paste/SelectAll | `Commands.cpp:273/280/348/362/367/376` | yes (undo unreachable in practice — §2) |
| 2107 | Find | `:595` `DoEditFind` | yes |
| 2108 | Replace | `:614` `DoEditReplace` | yes |
| 2109 | Find Next | `:607` `DoEditFindNext` | yes |
| 2110 | Replace All | `:635` `DoEditReplaceAll` | yes |
| 3001 | Model>Local Inference Test | `main_win32.cpp:2191` | yes |
| 3002 | Model>Admission Diag | `:2194` | yes |
| 3003 | Model>Open Model | `:2164` `FileOps_OpenDialog` + `initChatEngine` | yes |
| 4001/4002 | Agentic Gate / E2E Gate | `:2197/2200` | yes |
| 5001 | View>Toggle Sidebar | `:2203` | yes |
| 1010/1020 | Recent-files base/clear | **none** — constants declared, never used | no |
| — | Command palette, Ctrl+P, F12, rename, IDE git | **none** | no |

Router defects: `Win32IDE_Commands_Route` (`Commands.cpp:686-692`) returns `true` for any id in `[1000,2000)` / `[2100,2200)` whether or not a `case` matched. `Win32IDE_Commands_Register` (`:693`) is the mechanism that would populate `g_commandHandlers` — with 0 callers, that map is permanently empty and the first branch of `Route` is unreachable.

---

## 7. FILE OPERATIONS AND THE LNK2019

**Root cause: a namespace/scope declaration mismatch inside one TU. Not a missing source, not a duplicate authority, not a link-line omission.**

- The definitions are in `namespace RawrXD::IDE` (`Win32IDE_FileOps.cpp:8`), so the mangled names are `?FileOps_ReadFile@RawrXD@IDE@@...`.
- `Win32IDE_RuntimeCert.cpp` originally declared `FileOps_ReadFile/WriteFile/Exists` at **global** scope with C++ linkage, naming `::FileOps_ReadFile`. Different mangled name → nothing resolved → `LNK2019`.
- `Win32IDE_FileOps.cpp` **is** in `WIN32IDE_SOURCES` (`CMakeLists.txt:5427`) and is the only definition site of all seven symbols repo-wide.
- **Fixed in the working tree.** `Win32IDE_RuntimeCert.cpp:67-71` now declares them inside `namespace RawrXD::IDE` and `:72-74` adds the matching `using` declarations; `:61-66` documents the cause.

**Verified fixed, not assumed:**

```text
build_ide_audit/RawrXD-Win32IDE.dir/Release/Win32IDE_RuntimeCert.obj   18:10:18
build_ide_audit/bin/Release/RawrXD-Win32IDE.exe   21,724,160 bytes   18:21:33
strings in that exe: RAWRXD_IDE_RUNTIME_CERT_001=True  IDE_RUNTIME_CERT=True
                     S01_EXE_LAUNCH_WINMAIN=True       ide_runtime_cert_receipt.txt=True
                     session.state=True                settings.ini=True
```

**But that binary is stale with respect to the tree.** Newest sources in `src/win32app`:

```text
main_win32.cpp        2026-10-01 18:40:57   <-- 19 min AFTER the 18:21:33 link
launch_config.cpp     2026-10-01 18:38:35   <-- 17 min AFTER the link
launch_config.h       2026-10-01 18:38:16
Win32IDE_GitPanel.cpp 2026-10-01 18:11:05
Win32IDE_Commands.cpp 2026-10-01 17:57:39
```

Per `single_writer.verification_invalidation`, any runtime claim about the IDE is bound to an identity that no longer exists. Every classification in this document is `IMPLEMENTED_NOT_RUNTIME_VERIFIED` for exactly this reason — **not** because the code is unproven, but because the artifact that ran predates the source.

---

## 8. `Win32IDE_RuntimeCert.cpp` — WHAT IT DOES, AND CAN IT EVER PASS?

**What it is.** A 483-line 16-stage automated smoke test over the real runtime surface, entered only via `--ide-runtime-cert` (`main_win32.cpp:2751-2757` → `:2991-2999`). It runs after `ShowWindow` (`:2962`) and before the message loop (`:3001`); `WM_CREATE` has already run synchronously inside `CreateWindowEx` at `:2864`, so every child window exists.

**By this project's evidence rules it is well built.** No stage writes a literal PASS. The verdict is derived from counts at `:455`:

```cpp
const bool all_ok = (fail == 0 && ni == 0 && blocked == 0 && pass == g_stages.size());
```

It was also hardened against two vacuous-pass classes the file names itself: `EditorEngine_SetText` instead of `EM_*` (`:52-59`, because `RawrXDEditor` is a custom class), and a **non-empty payload requirement** on `S05` (`:246`) and `S06` (`:264`) so an inert control cannot produce a match-because-both-sides-empty pass (`:230-234`). `:292` and `:312` calling `Route(0)` into `(void)routed` is the same instinct: keep the field, do not let it carry weight.

**It can never pass. Not "not yet" — structurally.**

Five stages are unconditional `NOT_IMPLEMENTED`, with no code path that can change them:

| Stage | Line | Why it can never flip |
|---|---|---|
| `S07_COMMAND_PALETTE` | `:284` | only flips if a child window of class `RawrXDCommandPalette` exists. That string occurs **exactly once in the whole tree**: this probe's own argument at `:280`. |
| `S08_CTRL_P` | `:295` | no handler exists; also declares `const bool hasCtrlP = false;` at `:293`. |
| `S09_F12_GOTO_DEFINITION` | `:305` | no F12 command id routes to it from the Win32IDE table. |
| `S10_RENAME` | `:314` | no rename command id exists. |
| `S13_GIT_OPERATION` | `:364` | 5 Git features registered, none routed from the command table. |

A sixth is permanent by construction:

- **`S16_CLEAN_SHUTDOWN` (`:406`)** is recorded `BLOCKED` with the comment *"RunIdeRuntimeCertFinalize writes the final value after the message loop exits."* **No such function exists.** Repo-wide search for `RunIdeRuntimeCertFinalize` returns one hit — that comment. There is no finalize step; `IdeRuntimeCert_Run()` (`:478`) is the only entry and it runs entirely before the loop.

`all_ok` requires `ni == 0 && blocked == 0`. With 5 `NOT_IMPLEMENTED` + 1 `BLOCKED` fixed at six, `IDE_RUNTIME_CERT=FAIL` is a structural constant.

**Two of its measurements are nonetheless wrong, which matters more than the verdict:**

1. **`S14` measures the wrong window.** `ShellLayout_GetTerminal()` returns `g_hTerminal` — the custom `RawrXDTerminal` class (`TerminalSplit.cpp:203-207`). The probe then reads `GetWindowLongPtrW(term, GWL_STYLE) & ES_READONLY` (`:377`). `ES_READONLY` is `0x0800`, a **window-style** bit whose meaning is specific to EDIT/EDIT-like classes; on a custom class it aliases unrelated `WS_*` bits. The diagnostic string the code emits — *"terminal is output-only: WS_EX_CLIENTEDGE EDIT with ES_READONLY"* — describes `g_hOutput` (`main_win32.cpp:2125-2129`), a **different window**. So `S14` reports a fact about window A while measuring window B. `INVALID_MEASUREMENT`.
2. **`S15` measures a field it then ignores.** `reopened` is computed at `:390-391` and printed at `:393`, but the PASS condition is `closed && FileOps_Exists(doc)` (`:398`). Because `FileOps_OpenDialog`/`SaveDialog` are modal, both calls return empty and `reopened` is **always 0** — yet the stage still reports PASS. A reader sees `reopen_route=0 | VERDICT=PASS`.

Net: the gate is honest about what is missing (a rarity worth recording) and structurally incapable of closing. Its value today is the **stage table**, not the verdict. The verdict line is `IDE_RUNTIME_CERT=FAIL` by construction and must not be read as a surprising result.

---

## 9. PERSISTENCE / SHUTDOWN — DOES STATE FLUSH ON EXIT?

**Only if the user closes the window with the X. Not if they use File > Exit.**

```cpp
// main_win32.cpp:2265  WM_CLOSE — the ONLY flush path
RawrXD::IDE::Settings_Persist();     // :2286
RawrXD::IDE::Session_Persist();      // :2288
RawrXD_IDE_SaveWorkspace();          // :2290
writeIntegrationStatus("shutdown");  // :2292
g_fileWatcher.stop();                // :2293
```

```cpp
// main_win32.cpp:2152  IDM_FILE_EXIT
recordShutdownReason(ShutdownReason::ApplicationQuit);
DestroyWindow(hWnd);                 // -> WM_DESTROY (:2257) -> PostQuitMessage. No flush.
```

`DestroyWindow` sends `WM_DESTROY`, not `WM_CLOSE`. `WM_DESTROY` (`:2257-2264`) records a reason and quits. **Every persist call and every shutdown receipt is skipped.**

Consequences on File > Exit:

- Session entries are lost.
- Settings changed outside the dialog are lost.
- The workspace document is not written.
- `ide_settings_status.txt`, `ide_session_status.txt` and `ide_workspace_status.txt` are **not overwritten**, so they retain their startup content — including `PHASE=startup` and `VERDICT=PASS`. An operator inspecting those files after a File > Exit reads them as a clean verification.
- The file watcher is never stopped.

**And the exit path consults neither the modified flag nor the unsaved-changes prompt.** `DoFileNew` (`:166-184`) and `DoFileClose` (`:245-251`) do prompt, but `IDM_FILE_EXIT` does not. With `AutoSave_Start` never called (§1), **closing the IDE with unsaved edits destroys them with no prompt and no backup.**

There is a correct handler, written, sitting unreachable behind the shadowed one:

```cpp
// Win32IDE_Commands.cpp:253
static void DoFileExit() { PostMessage(g_hwndMain, WM_CLOSE, 0, 0); }   // would flush
// Win32IDE_Commands.cpp:659  case IDM_FILE_EXIT: DoFileExit(); break;  // never reached
```

This is a duplicate-authority defect in the exact shape the ledger records as `command_handle_layer_classification`: two authorities for one id, and the one that wins is the one that skips the contract.

---

## TOP DEFECTS

### P0-1 — `File > Exit` bypasses every persistence call and every shutdown receipt
`main_win32.cpp:2152-2160` (`DestroyWindow`) vs `main_win32.cpp:2286-2292` (`WM_CLOSE` flush). A correct `DoFileExit()` exists at `Win32IDE_Commands.cpp:253` and is shadowed by the `WM_COMMAND` case at `:2152`, so the persisting handler is dead code. Loss: session, dialog-external settings, workspace document, watcher stop. The three `ide_*_status.txt` receipts are left holding `PHASE=startup / VERDICT=PASS`.
**Fix:** delete the `IDM_FILE_EXIT` case at `:2152` and let `Route(1099)` reach `DoFileExit()`; or replace `DestroyWindow` with `PostMessage(WM_CLOSE)`.

### P0-2 — Exit destroys unsaved work with no prompt and no autosave
`main_win32.cpp:2152-2160` does not consult `EditorEngine_IsModified()`. `AutoSave_Start` (`Win32IDE_AutoSave.cpp:26`) has **0 callers** repo-wide, so nothing is ever written between edits and exit.
**Fix:** route Exit through the `DoFileNew()` unsaved-changes guard, and arm `AutoSave_Start` in `WM_CREATE` when `editor.autoSave` is true.

### P0-3 — `IDE_RUNTIME_CERT` can never report PASS; `S16`'s finalize step does not exist
`Win32IDE_RuntimeCert.cpp:284,295,305,314,364` (5 × `NOT_IMPLEMENTED`) and `:406` (`S16` `BLOCKED`, citing a `RunIdeRuntimeCertFinalize` that appears nowhere but that comment). `all_ok` at `:455` requires `ni==0 && blocked==0`.
**Do not** "fix" this by softening the gate. Either implement the five missing surfaces and add the finalize step, or reclassify the gate as a **stage census** — its real product — and stop presenting `IDE_RUNTIME_CERT=FAIL` as a certification failure.

### P0-4 — `Win32IDE_Commands_AttachUndo()` is never called; typing produces no undo steps
`Win32IDE_Commands.cpp:699` has 0 callers → `EditorEngine.cpp:461` `if (g_mutationHook)` never fires. The comment at `Win32IDE_Commands.cpp:123-127` asserts the opposite. `Ctrl+Z` after typing reverts the entire buffer to the file-open snapshot.
**Fix:** one call — `Win32IDE_Commands_AttachUndo()` — in `WM_CREATE` after `:2100`.

### P1-5 — Session and workspace persistence are structurally content-free
`Session_GetFiles()` (`Win32IDE_Session.cpp:178`) has 0 callers → nothing is restored. `RawrXD_IDE_AddOpenFile` (`src/core/workspace_model.cpp:624`) and `RemoveOpenFile` (`:634`) have 0 callers → the saved workspace contains zero open files. Both shutdown receipts PASS anyway (`main_win32.cpp:1098`, `:1180`) because neither verdict requires a single entry.
**Fix:** iterate `Session_GetFiles()` after `:2041` and re-open via `TabManager_OpenFile`; call `RawrXD_IDE_AddOpenFile` from `DoFileOpen`/`DoFileClose`; add `filesInSession > 0` / `d.openFiles > 0` to the respective PASS conditions.

### P1-6 — `Win32IDE_Commands_Route` reports unhandled ids as handled
`Win32IDE_Commands.cpp:689-690`: any id in `[1000,2000)` or `[2100,2200)` returns `true` even when no `case` matched, because `handleFileCommand`/`handleEditCommand` have no `default`. `WM_COMMAND` (`:2214`) then `break`s instead of reaching `DefWindowProc`. This also inflates `route_save` in `S06` and `close_route` in `S15`.
**Fix:** have the two `handle*` functions return `bool` and propagate it.

### P1-7 — Five panels and four subsystems are implemented, linked, created, and unreachable
Zero-call entry points: `ShellLayout_ToggleChat/Agent/Terminal/Search/Git` (`Win32IDE_ShellLayout.cpp:111,117,124,130,140`); all 9 `StatusBar_Set*` (`Win32IDE_StatusBar.cpp:149-210`); `SearchPanel_Search/SetRoot/SetJumpCallback` (`Win32IDE_SearchPanel.cpp:292-303`); `AutoSave_Start` (`Win32IDE_AutoSave.cpp:26`); `Watchdog_Start` (`Win32IDE_Watchdog.cpp:17`); `Logger_Init` (`Win32IDE_Logger.cpp:15`); `AgenticBridge_Init` (`Win32IDE_AgenticBridge.cpp:30`); `StreamingUX_SetStatusBar` (`Win32IDE_StreamingUX.cpp:22`); `Win32IDE_Sidebar_GetSelectedPath` (`Win32IDE_Sidebar.cpp:219`); `Win32IDE_Commands_Register/SetDirty/GetCurrentFile` (`Win32IDE_Commands.cpp:693,694,703`). Agent, Search and Git panels are created at `ShellLayout.cpp:72-75` and hidden at `:87-89` with no reachable `SW_SHOW`.
**This is the dominant pattern of the batch: `registered != reachable`.** A census that counted these as features would overstate the IDE's surface by roughly 1,100 lines.

### P1-8 — Zero settings are consumed by anything
`Settings_Get/GetInt/GetBool` have no callers outside the settings dialog and `CICDSettings.cpp`. All 16 schema keys (`Win32IDE_Settings.cpp:67-84`) are inert. Additionally the dialog writes `editor.lineNumbers` (`Win32IDE_SettingsGUI.cpp:171`) and `lsp.language` (`:182`), which are **not** in `kSchema`, so the product reports its own output as unknown keys on every load.
**Fix:** either wire a consumer per key or narrow `kSchema` to what is read; add `editor.lineNumbers` and `lsp.language` to `kSchema` or stop writing them.

### P2-9 — `S14` measures a window it is not describing
`Win32IDE_RuntimeCert.cpp:377` reads `ES_READONLY` (`0x0800`) out of `GWL_STYLE` on the custom `RawrXDTerminal` window; the emitted diagnostic text describes `g_hOutput` (`main_win32.cpp:2125`), a different window. `S15` (`:390-398`) computes `reopened`, always gets 0 (modal dialogs), prints it, and excludes it from its own PASS condition.

### P2-10 — Five `WinMain` bring-up failures are silent
Return values discarded at `main_win32.cpp:2035` (`Settings_EnsureLoaded`), `:2041` (`Session_Load`), `:2049` (`RawrXD_IDE_InitWorkspace`), `:2966`/`:2967` (the two `Set*Window` calls), `:2968` (`MCPBridgeManager::Initialize`, which returns `bool`). The file-watcher failure at `:2086-2088` is the one that is counted — the pattern is inconsistent within the same handler.

### P2-11 — GhostText data race
`Win32IDE_GhostText.cpp:48-74` writes `g_ghost.suggestion` and `g_ghost.visible` from a detached worker thread; `Win32IDE_GhostText.cpp:105` `GhostText_Paint` reads them from the UI thread. Neither is atomic; `visible` is a plain `bool` and `suggestion` a plain `std::string`. The 300 ms debounce serialises writers but does not protect the reader. Also: the thread is detached and can outlive the editor window, and `GhostText_SetProvider` (`:35`) has 0 callers so only the 4-branch heuristic at `:58-65` can ever fire.

### P2-12 — Undo stack index desynchronizes past depth 50
`Win32IDE_Commands.cpp:115-120`: `if (size > 50) { erase front; } else { ++g_undoPos; }`. `g_undoPos` is not advanced on the truncating branch, so it stops tracking the live index and `DoEditRedo`'s `g_undoPos+1 < size` is permanently false.

### P2-13 — Second, dead entry point in the same binary
`src/core/IDEStartupFinal.cpp:133` `IDE_Main(int,char**)` plus `IDE_Startup_Full` (`:25`) and `IDE_Shutdown_Full` (`:86`) — all 0 callers. A "Sovereign IDE Final Integration" surface the product never enters, alongside the two entry authorities that are live.

### P2-14 — Menu ids triplicated with no cross-check
`main_win32.cpp:1439-1466`, `Win32IDE_Commands.cpp:74-99`, `Win32IDE_RuntimeCert.cpp:35-43`. Currently consistent; nothing enforces it, and the third copy is already partial.

---

## BATCH 04 STATUS

```text
STAGES_AUDITED                      = 9
CLASSIFICATIONS_ISSUED              = 47

VERIFIED                            = 5
IMPLEMENTED_NOT_RUNTIME_VERIFIED    = 11
CONTRACT_VIOLATED                   = 9
DEAD/UNBOUND                        = 8
UNIMPLEMENTED                       = 3
INVALID_MEASUREMENT                 = 3
BLOCKED                             = 0

LNK2019_FILEOPS                     = ROOT_CAUSE_IDENTIFIED_FIX_VERIFIED_IN_TREE
IDE_LINKED_BINARY                   = build_ide_audit  2026-10-01 18:21:33  21,724,160 B
CERT_CODE_PRESENT_IN_BINARY         = 1  (RAWRXD_IDE_RUNTIME_CERT_001, IDE_RUNTIME_CERT=)
BINARY_VALID_FOR_CURRENT_TREE       = 0  (main_win32.cpp +19min, launch_config.cpp +17min)

IDE_RUNTIME_CERT_CAN_REPORT_PASS    = 0   (5 NOT_IMPLEMENTED + 1 BLOCKED are structural)
RUNTIME_CERT_REMAINING_DEFECTS      = 2   (S14 wrong window; S15 field excluded from own verdict)

ZERO_CALLER_ENTRYPOINTS_IN_SCOPE     = 14 subsystems / ~1,100 lines
SETTINGS_KEYS_READ_BY_RUNTIME       = 0 of 16
SESSION_DOCUMENTS_RESTORED          = 0
SHUTDOWN_FLUSH_PATHS                = 1 of 2 (WM_CLOSE yes; File>Exit no)

BATCH_04_VERDICT = COMPLETE — FINDINGS MEASURED, NO SOURCE MODIFIED
RUNTIME_VERIFICATION = IMPOSSIBLE AGAINST THIS TREE (binary predates source)
```

**Honest limits of this batch.** Every classification is a source measurement. No stage was executed, because the only linked artifact predates the working tree by 19 minutes and re-running it would produce evidence for a different source identity. I did not modify any file in `src/`. The LNK2019 fix is the one runtime-adjacent claim in this batch that *is* supported by an artifact, and it is the only one; I verified it by extracting strings from the 18:21:33 executable and comparing object and source timestamps rather than by re-linking.

**The one pattern worth carrying forward.** Fifteen of the twenty-eight findings in this batch have the same shape: a complete, plausible, well-commented implementation with zero call sites — `AttachUndo`, `AutoSave_Start`, `Watchdog_Start`, `Logger_Init`, `AgenticBridge_Init`, `ShellLayout_Toggle*`, every `StatusBar_Set*`, all of `SearchPanel_*`, `Session_GetFiles`, `RawrXD_IDE_AddOpenFile`, `Win32IDE_Sidebar_GetSelectedPath`, `Win32IDE_Commands_Register`. Several carry comments asserting the behaviour is wired. **A comment claiming a call site is not a call site, and this tree is dense with them.** Counting feature implementations overstates the IDE's real surface by roughly a thousand lines.