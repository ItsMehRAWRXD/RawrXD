# PowerShell Panel Routing Audit (sealed)

```text
AUDIT_ID=INTEG_004_HIDDEN_AUDIT_20261109
DOC=POWERSHELL_PANEL_ROUTING_AUDIT.md
ASOF_UTC=2026-11-09T14:40:00Z
WORKSPACES=G:\~dev\rawrxd ; F:\rawrxd
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNTIME_PASS=0
PASS_INVENTED=0
MATURITY=82%
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
CONTROLLING_TIP=CC79 (identity only; not panel ls acceptance)
GITHUB_MAIN_NE_RUNNING_BINARY=1
TERM_SMOKE_NE_PS_PANEL=1
LAW=NOT_RUN != PASS ; SOURCE_WIRED != RUNTIME_REACHED
PANEL_NE_TERMINAL=1
```

Supersedes interim notes in `POWERSHELL_PANEL_ROUTING_INTERIM.md` with cited line numbers.
Does **not** tip-move. Does **not** invent PASS. Optional rebuild only after a fix + NEW SHA remasure.

---

## 1. Fail-closed disposition

| Claim class | Disposition |
|---|---|
| Source wiring of PowerShell panel (STATIC + WndProc) | **SOURCE_WIRED** (confirmed below) |
| Welcome / banner text in RichEdit | **SOURCE_WIRED** ≠ command exec proved |
| Panel `ls` → listing in panel | **NOT_RUN** / **OPEN** |
| Chat transcript untouched during panel `ls` | **NOT_RUN** / **OPEN** |
| ConPTY `--term-smoke` | Separate surface; **≠** panel acceptance |
| Product / promote | **PROMOTE=0** · maturity **82%** |

---

## 2. CONFIRMED source findings (file:line)

### 2.1 F:\rawrxd — ANSI RichEdit path still live

| Finding | Cite |
|---|---|
| STATIC container via ANSI `CreateWindowEx` | `F:\rawrxd\src\win32app\Win32IDE_PowerShellPanel.cpp:97-105` (`"STATIC"`, `"PowerShell Console"`) |
| `SetWindowLongPtr` installs `PowerShellPanelProc` on STATIC | `…:118-121` |
| Output control = `RichEdit20A` | `…:127-131` (`LoadLibrary("Riched20.dll")`, class `"RichEdit20A"`) |
| Append via ANSI `SendMessage` + `EM_REPLACESEL` | `…:554-564` (`EM_SETSEL` / `EM_SETCHARFORMAT` / `EM_REPLACESEL` with `cleaned.c_str()`) |
| VT strip before RichEdit (CSI/`[?…` litter awareness) | `…:13-28` (`stripVtForRichEdit`); applied at `…:547-548` |
| Comment: ConPTY CSI → duplicate `PS>` + `[?25l` litter | `…:656-657` |
| Prompt literal `PS> ` | `…:793-794` (`getPowerShellPrompt`) |
| Echo before execute: `getPowerShellPrompt() + command` | `…:476` |
| Welcome banner + prompt appended at create | `…:203` region; prompt append `…:218` |
| `PowerShellPanelProc` definition present | `…:808` |

**GitHub claim “RichEdit20A + SendMessage ANSI risk”:** **CONFIRMED on F tree.**

**GitHub claim “PowerShellPanelProc unused on STATIC”:** **STALE vs F** — proc **is** installed (`:118-121`).

### 2.2 G:\~dev\rawrxd — Unicode RichEdit path ahead of F / GitHub ANSI claim

| Finding | Cite |
|---|---|
| STATIC container via `CreateWindowExW` | `G:\~dev\rawrxd\src\win32app\Win32IDE_PowerShellPanel.cpp:76-84` (`L"STATIC"`) |
| `SetWindowLongPtrW` → `PowerShellPanelProc` | `…:116-119` |
| Msftedit first, `RICHEDIT_CLASSW` fallback | `…:124-148` (`LoadLibraryW(L"Msftedit.dll")`, `MSFTEDIT_CLASS`, then `RICHEDIT_CLASSW`) |
| Unicode append: UTF-8 → wide → `SendMessageW` `EM_REPLACESEL` | `…:634-656` |
| Prompt literal `PS> ` | `…:882-883` |
| Echo before execute | `…:578` |
| Welcome banner block (render ≠ exec proof) | `…:229-242` |
| Dedicated session `onOutput` → `appendPowerShellOutput` only | `…:327-363` |
| **Routing fork:** panel command prefers **active terminal tab** `writeInput` before dedicated PS session | `…:589-608` |
| `PowerShellPanelProc` definition | `…:897` |
| No `stripVtForRichEdit` symbol in G win32app (F-only filter) | search: **absent** on G |

**GitHub ANSI RichEdit claim:** **does not match G tree source** (Unicode path). May still match **running tip EXE** if binary was built from F / older SHA — `GITHUB_MAIN_NE_RUNNING_BINARY=1`.

### 2.3 Chat / Output routers (G) — no literal `[powershell]` tag

| Finding | Cite |
|---|---|
| `m_chatMode` ON → `appendChatMessage` + model thread | `Win32IDE.cpp:2553-2571` |
| Non-chat command → active `TerminalPane` `writeInput` | `Win32IDE.cpp:2574-2580` |
| `toggleChatMode` / status bar Chat vs Terminal | `Win32IDE.cpp:5915-5947` |
| `appendChatMessage` → **`appendToOutput(..., "Output", ...)`** (not sidebar EDIT alone) | `Win32IDE.cpp:5950-5974` |
| AgentChatPane dump documents same Output sink | `AgentChatPane_Dump.hpp:58-66` |
| Inference worker / ProductDeep2 stream (near :6831) | `Win32IDE.cpp:6827-6862` — **not** chat↔terminal toggle; user “~6831” maps to Deep2 stream, multiplex is `:2553` / `:5915` |
| Literal `"[powershell]"` in win32app sources | **NOT FOUND** (scan 2026-11-09) |
| Example agentic tool→chat append uses `event.toolName` | `src/agentic/StreamingIntegrationExamples.h:65-82` (`appendToChatPanel(... + event.toolName + ...)`) — example / commented pattern; **not** a sealed product wire |

### 2.4 Term smoke ≠ panel (evidence already on disk)

| Receipt | Result | Panel `ls`? |
|---|---|---|
| `receipts/TERM_SMOKE_2CCA_RECEIPT.txt` | `TERMINAL_ON_2CCA=PASS` · `ONESHOT_CONPTY=PASS` · **PROMOTE=0** | **No** — ConPTY oneshot only |
| `receipts/TERM_SMOKE_B39E_RECEIPT.txt` | `TERMINAL_ON_B39E=FAIL` (exit `-1073741510`) · **PROMOTE=0** | **No** |
| `TRACK_STATUS.md` INTEG_006 Chat+Term note | Tip identity / other track; **≠** this panel audit PASS | **No** |

---

## 3. UNVERIFIED runtime symptoms

User-reported; **no SHA-bound panel remasure in this seal.**

| Symptom | What it would establish if reproduced on NEW SHA | Current |
|---|---|---|
| `[powershell] ?` in AI/chat transcript | Shell-related / CSI / tool-tag text crossed into chat surface | **UNVERIFIED** |
| `ls` → `PS> PS> ?` | Echo + shell prompt collision and/or failed exec / CSI residue | **UNVERIFIED** (execution **not** proved) |
| Other tabs clickable but blank | Selection chrome OK; producers idle / unwired | **UNVERIFIED** |
| Welcome banner visible | Init `appendPowerShellOutput` path reached HWND | **SOURCE plausible**; **≠** command exec |

Blank idle tabs ≠ defect. Clickable tabs ≠ working producers. Banner ≠ `ls` PASS.

---

## 4. INVESTIGATE — chat pollution suspects

Ordered by source proximity (still **OPEN**):

1. **Chat ↔ terminal multiplex** — `m_chatMode` (`Win32IDE.cpp:2553-2580`, `:5915-5947`). Panel `ls` must not enter this path; if command input is shared, mis-mode → chat pollution.
2. **`appendChatMessage` → Output panel** (`:5950-5974`) — anything labeled chat may still land in Output; cross-read as “AI transcript.”
3. **Agent tool transcript tags** — `StreamingIntegrationExamples.h:65-82` pattern `appendToChatPanel(… + toolName …)`. If a live bridge emits toolName `powershell`, UI can show powershell-tagged lines (encoding may yield `?` glyphs). **No** literal `[powershell]` string located in win32app.
4. **ConPTY CSI misread** — F explicitly documents `[?25l` litter (`PowerShellPanel.cpp:656-657`). Stripped ESC sequences or partial CSI (`[?`) can present as `?` / tag-like fragments if ESC lost before RichEdit/chat.
5. **Dual echo / dual surface** — G echoes `PS> ` in panel (`:578`) then `writeInput` to **active terminal tab** (`:589-596`) **or** dedicated session (`:607`). Shell may also emit its own prompt → `PS> PS>` class symptom. Tab ConPTY view vs panel RichEdit can diverge (blank tab / busy panel).
6. **Output vs Chat routers** — AgentChatPane sidebar EDIT vs `appendToOutput` Output channel (`AgentChatPane_Dump.hpp:58-71`); confirm which HWND user calls “AI/chat transcript.”

---

## 5. Panel ≠ Terminal law

```text
PANEL  = Win32IDE PowerShell panel HWND path
         (createPowerShellPanel / executePowerShellPanelCommand /
          appendPowerShellOutput / dedicated or tab writeInput)
TERMINAL = ConPTY / Win32TerminalManager oneshot (--term-smoke)
CHAT   = m_chatMode / appendChatMessage / Copilot sidebar / agent tool events

PASS(term-smoke)  ≠  PASS(panel ls)
PASS(banner)      ≠  PASS(panel ls)
SOURCE_WIRED      ≠  RUNTIME_REACHED
RUNTIME_REACHED   ≠  PRODUCT_PASS
PRODUCT_PASS      ≠  PROMOTE
```

INTEG_006 / tip Chat+Term notes are **out of scope** for sealing panel `ls` acceptance.

---

## 6. Acceptance criteria — LEFT OPEN

```text
AC1  Focus PowerShell panel input on SHA-bound tip EXE
AC2  Enter: ls
AC3  Directory listing appears in PowerShell panel RichEdit (same HWND)
AC4  AI/chat transcript HWND content unchanged (no [powershell]/ no ?)
AC5  No duplicate dead PS> PS> with failed/empty body (or explain as expected echo+shell)
AC6  Record: EXE path, SHA256, UTC, screenshot/log excerpt, PROMOTE=0

UNTIL AC1–AC6 measured on NEW SHA: RUNTIME_PASS=0 ; PRODUCT_PASS=0
```

Other channels: each producer → selected pane only — **OPEN** (not claimed here).

---

## 7. Tree divergence summary

| Topic | F:\rawrxd | G:\~dev\rawrxd | GitHub main (stale risk) |
|---|---|---|---|
| RichEdit | `RichEdit20A` + ANSI `SendMessage` | Msftedit / `RICHEDIT_CLASSW` + `SendMessageW` | ANSI claim ≈ F, **not** G |
| WndProc on STATIC | Installed `:118-121` | Installed `:116-119` | “unused” **STALE** |
| VT strip | `stripVtForRichEdit` present | **Absent** (search) | N/A |
| Prompt | `"PS> "` | `"PS> "` | Duplicate-echo **INVESTIGATE** |
| Panel command route | (session path; verify at remasure) | Prefer active **tab** then dedicated `:589-608` | N/A |

Authority for **next fix/remasure:** treat **G tree** as forward source unless tip EXE SHA proves F ancestry.

---

## 8. Next measurement (required)

```text
1. Identify tip EXE + Get-FileHash SHA256 (do not reuse term-smoke SHA as panel PASS)
2. Launch tip; open PowerShell panel; confirm banner only (note ≠ PASS)
3. Type ls → Enter in PANEL input (not chat, not separate ConPTY tab unless that IS the panel sink)
4. Capture panel RichEdit text (listing?) + chat/Output text (untouched?)
5. Write receipt under this folder: receipts/PS_PANEL_LS_<SHA8>_RECEIPT.txt
6. Keep PROMOTE=0 ; TIP_CLIMB=HOLD ; no tip-move from this audit alone
```

Optional rebuild **only if** a source fix lands **and** remasure runs on the **NEW** SHA.

---

## 9. Authority footer

```text
PROMOTE=0
MATURITY=82%
CERTIFIED=0
PRODUCT_PASS=0
RUNTIME_PASS=0
PASS_INVENTED=0
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
TERM_SMOKE_NE_PS_PANEL=1
PANEL_NE_TERMINAL=1
AUDIT_VERDICT=SEALED_FAIL_CLOSED_OPEN_ACCEPTANCE
NEXT_GATE=PS_PANEL_LS_SHA_BOUND_MEASUREMENT
```
