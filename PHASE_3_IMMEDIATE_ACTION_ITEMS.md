# Qt to MASM Conversion - IMMEDIATE ACTION ITEMS & BLOCKERS

**Date**: December 28, 2025  
**Document Purpose**: Clear, actionable list of what needs to be done RIGHT NOW  
**Audience**: Development team ready to continue Phase 3  

---

## CURRENT STATE (Dec 28, 2025)

### ✅ COMPLETED
- 11 core files successfully compiling
- 147 KB pure x64 MASM object code generated
- All basic infrastructure in place (memory, strings, events, logging)
- Qt object model (OBJECT_BASE) fully implemented in MASM
- Basic text editor (multi-line, cursor, selection) working
- Syntax highlighting framework operational

### ❌ BLOCKING FURTHER PROGRESS
These 3 systems must be implemented before major UI components can proceed:

1. **Dialog System** - Blocks: settings_dialog, file browser, color picker, font selector
2. **Tab Control System** - Blocks: settings_dialog (7 tabs), multi-tab editor
3. **Common Controls Wrappers** - Blocks: list views, tree views, combo boxes, sliders

---

## PHASE 3 CRITICAL PATH

### BLOCKER #1: Modal Dialog System
**Current Status**: Non-existent  
**Est. Size**: 800-1000 MASM LOC  
**Implementation Time**: 2-3 days for experienced MASM dev  
**Blocks**: 15+ components

**Must Implement**:
```asm
; Core functions
DialogSystemInit()           ; Initialize dialog subsystem
CreateModalDialog()          ; Create + run modal dialog
CreateModelessDialog()       ; Floating window
DialogMessageLoop()          ; Message routing for dialogs
RegisterDialogWindowClass()  ; WC_DIALOG equivalent
```

**Why This First?**:
- Used by settings_dialog (most critical remaining component)
- Used by file open/save dialogs
- Used by color/font pickers
- Used by any confirmation/alert boxes
- ~20+ remaining components depend on this

**Implementation Approach**:
1. Study Windows DialogBox API
2. Create dialog message routing (separate from main loop)
3. Handle WM_INITDIALOG, WM_COMMAND, WM_CLOSE
4. Implement modal focus (disable parent, capture input)
5. Return dialog result to caller

**File Location**: `src/masm/final-ide/dialog_system.asm` (create new)

---

### BLOCKER #2: Tab Control System
**Current Status**: Non-existent  
**Est. Size**: 1000-1200 MASM LOC  
**Implementation Time**: 2-3 days  
**Blocks**: 12+ components (especially settings_dialog with 7 tabs)

**Must Implement**:
```asm
; Tab operations
CreateTabControl()           ; WC_TABCONTROL window
AddTabPage()                 ; Add page with title
RemoveTabPage()              ; Delete page
GetActiveTabPage()           ; Get current page index
SetActiveTabPage()           ; Switch to page N
OnTabPageSelected()          ; Handle TCN_SELCHANGE
```

**Why This Second?**:
- Settings dialog REQUIRES 7 tabs (General, Model, Chat, Security, Training, CI/CD, Enterprise)
- Multi-file editor uses tabs
- Without this, settings dialog can't be implemented

**Implementation Approach**:
1. Use WC_TABCONTROL from comctl32
2. Create TAB_CONTROL structure to track pages
3. Send TCM_INSERTITEM to add pages
4. Show/hide child windows based on active page
5. Handle TCN_SELCHANGE notifications

**File Location**: `src/masm/final-ide/tab_control.asm` (create new)

---

### BLOCKER #3: Common Controls Wrappers
**Current Status**: Minimal  
**Est. Size**: 2000+ MASM LOC (total for all controls)  
**Implementation Time**: 4-5 days for complete set  
**Blocks**: File browser, model list, option dialogs

**Must Implement** (prioritized):

#### TIER 1 (CRITICAL - blocks multiple components)
```asm
CreateListView()             ; WC_LISTVIEW (file list, model list)
AddListViewColumn()          ; LVM_INSERTCOLUMN
AddListViewItem()            ; LVM_INSERTITEM
GetListViewSelection()       ; Get selected item
OnListViewSelectionChanged() ; LVN_ITEMCHANGED handler
```
**Why**: File browser, model selector, chat history all need lists

#### TIER 2 (IMPORTANT - needed soon)
```asm
CreateTreeView()             ; WC_TREEVIEW (file tree)
InsertTreeNode()             ; TVM_INSERTITEM
ExpandTreeNode()             ; Expand/collapse
GetSelectedTreeNode()        ; Get selection
```
**Why**: File browser needs directory tree

#### TIER 3 (USEFUL - nice to have)
```asm
CreateComboBox()             ; Dropdown list
CreateSliderControl()        ; Range slider
CreateSpinnerControl()       ; Up/down spinner
CreateProgressBar()          ; Progress indicator
```

**File Locations**:
- `src/masm/final-ide/listview_control.asm` (create new)
- `src/masm/final-ide/treeview_control.asm` (create new)
- `src/masm/final-ide/common_controls.asm` (create new)

---

## IMMEDIATE NEXT STEP: Build Dialog System

### Create File: `src/masm/final-ide/dialog_system.asm`

**Skeleton Code to Implement**:

```asm
; ============================================================================
; Dialog System Implementation
; ============================================================================
; Provides modal dialog support for RawrXD Pure MASM IDE
; Blocks all dialog-dependent components
; ============================================================================

include windows.inc
include kernel32.inc
include user32.inc
include comctl32.inc

.CODE

; ============================================================================
; DialogSystemInit: Initialize dialog subsystem
; Parameters:
;   rcx = parent HWND (main window handle)
; Returns:
;   rax = success (0 = fail, 1 = success)
; ============================================================================
DialogSystemInit PROC
    ; Initialize dialog registry, allocate dialog tracking array
    ; Setup message loop flags
    ; Register dialog window class if needed
    
    mov rax, 1                  ; Success
    ret
DialogSystemInit ENDP

; ============================================================================
; CreateModalDialog: Create and run modal dialog
; Parameters:
;   rcx = parent HWND
;   rdx = dialog title (string pointer)
;   r8d = dialog width
;   r9d = dialog height
; Returns:
;   rax = dialog result (OK=1, Cancel=0, etc.)
; ============================================================================
CreateModalDialog PROC
    ; Create dialog window
    ; Show dialog
    ; Run message loop until dialog closes
    ; Return result code
    
    mov rax, 0                  ; Placeholder
    ret
CreateModalDialog ENDP

; ============================================================================
; DialogMessageLoop: Handle dialog-specific messages
; Parameters:
;   rcx = dialog HWND
;   rdx = message (WM_*)
;   r8 = wParam
;   r9 = lParam
; Returns:
;   rax = message result (0 or 1)
; ============================================================================
DialogMessageLoop PROC
    ; Route messages to appropriate handlers
    ; WM_INITDIALOG -> initialize controls
    ; WM_COMMAND -> button clicks, control input
    ; WM_CLOSE -> close dialog
    ; WM_DESTROY -> cleanup
    
    mov rax, 0                  ; Default message handling
    ret
DialogMessageLoop ENDP

; ============================================================================
; Additional dialog support functions follow...
; ============================================================================

END
```

**What Needs to Be Done**:

1. **Parse Windows COMCTL32 constants** (from windows.inc):
   - Control class names (WC_TABCONTROL, WC_LISTVIEW, etc.)
   - Messages (WM_COMMAND, etc.)
   - Notification codes (TCN_SELCHANGE, LVN_ITEMCHANGED, etc.)

2. **Implement dialog tracking** (data structure):
   ```asm
   DIALOG_ENTRY STRUCT
       hwnd            QWORD ?     ; Dialog window
       parent_hwnd     QWORD ?     ; Parent window
       on_command      QWORD ?     ; Command callback
       result          DWORD ?     ; Dialog result
       is_modal        BYTE ?      ; Modal/modeless flag
   DIALOG_ENTRY ENDS
   ```

3. **Implement core dialog operations**:
   - Dialog creation with CreateWindowExA
   - Message filtering/routing
   - Modal dialog focus management
   - Result propagation

4. **Add to build script** (`build_final.bat`):
   ```batch
   ml64 /c /Fo obj\ dialog_system.asm
   ```

5. **Link with libcmt.lib, kernel32.lib, user32.lib, comctl32.lib**

---

## NEXT PRIORITY AFTER DIALOG SYSTEM: Settings Dialog

### File to Convert: `src/qtapp/settings_dialog.cpp` (23,338 bytes)

**Why This Is Critical**:
- Controls all application settings
- Most accessed UI component after main editor
- 7 tabs covering all major systems
- Used by every MASM IDE feature

**Tabs to Implement** (in order):

1. **General Tab** (simple controls):
   - Auto-save checkbox
   - Startup behavior dropdown
   - Font size spinner

2. **Model Tab** (requires file browser):
   - Model path text input
   - Browse button → file dialog
   - Model list (requires list view)
   - Default model selector

3. **AI Chat Tab** (sliders + inputs):
   - Chat model dropdown
   - Temperature slider (0.0-1.0)
   - Max tokens spinner
   - System prompt text area

4. **Security Tab** (text inputs):
   - API key input (password field)
   - Encryption toggle
   - Secure storage checkbox

5. **Training Tab** (optional, deferred):
   - Training path browser
   - Checkpoint interval spinner
   - Batch size spinner

6. **CI/CD Tab** (optional, deferred):
   - Pipeline settings
   - GitHub token input

7. **Enterprise Tab** (optional, deferred):
   - Compliance logging toggle
   - Telemetry checkbox

**Estimated MASM Size**: 2,500 LOC

---

## COMPLETE ACTION PLAN (Next 2 Weeks)

### Week 1: Foundation Controls
**Monday-Tuesday**: Dialog System
- Create `dialog_system.asm` (800 LOC)
- Implement core dialog functions
- Test with simple message box

**Wednesday-Thursday**: Tab Control System  
- Create `tab_control.asm` (1,000 LOC)
- Implement tab creation/switching
- Test with 2-tab dialog

**Friday**: Test Integration
- Verify dialog + tab system working together
- Create test dialog with 3 tabs

### Week 2: Settings Dialog
**Monday-Wednesday**: Settings Dialog Implementation
- Create `qt6_settings_dialog.asm` (2,500 LOC)
- Implement General + Model + Chat tabs
- Add settings persistence (Registry)

**Thursday**: Theme System
- Create `qt6_theme_manager.asm` (1,000 LOC)
- Implement color palette management
- Support light/dark themes

**Friday**: Testing & Refinement
- Full settings dialog testing
- Theme switching verification
- Settings save/load validation

---

## COMPILE-TEST WORKFLOW FOR PHASE 3

### After Each Component

```powershell
# Test dialog system compilation
ml64 /c /Fo obj\ dialog_system.asm

# Test dialog + tab systems together
ml64 /c /Fo obj\ dialog_system.asm
ml64 /c /Fo obj\ tab_control.asm

# Test full Phase 3 UI framework
ml64 /c /Fo obj\ dialog_system.asm
ml64 /c /Fo obj\ tab_control.asm
ml64 /c /Fo obj\ listview_control.asm
ml64 /c /Fo obj\ qt6_settings_dialog.asm

# Full link
link /SUBSYSTEM:WINDOWS /ENTRY:_start obj\*.obj ...
```

---

## EXPECTED COMPILATION SUCCESS RATE

| Phase | Target | Expected Errors on First Pass | Estimated Fixes |
|-------|--------|-------------------------------|-----------------|
| Dialog System | 800 LOC | 2-3 | 30 mins |
| Tab Control | 1,000 LOC | 3-5 | 1 hour |
| ListViewControl | 1,200 LOC | 5-8 | 1.5 hours |
| Settings Dialog | 2,500 LOC | 8-12 | 2-3 hours |
| **Total Phase 3** | **~5,500 LOC** | **18-28** | **5-6 hours** |

**Note**: Based on Phase 2 patterns (99%+ error catch rate on first compile, mostly syntax/typos)

---

## FILES TO CREATE (Summary)

| # | Filename | Lines | Purpose | Priority |
|---|----------|-------|---------|----------|
| 1 | dialog_system.asm | 800 | Modal dialogs, message routing | **CRITICAL** |
| 2 | common_dialogs.asm | 600 | File/color/font dialogs | **CRITICAL** |
| 3 | tab_control.asm | 1,000 | Tabbed interface | **CRITICAL** |
| 4 | listview_control.asm | 1,200 | File lists, model lists | **HIGH** |
| 5 | treeview_control.asm | 1,000 | Directory trees, file browser | **HIGH** |
| 6 | qt6_settings_dialog.asm | 2,500 | Settings UI (7 tabs) | **HIGH** |
| 7 | qt6_theme_manager.asm | 1,000 | Color/theme system | **MEDIUM** |
| 8 | qt6_themed_editor.asm | 1,500 | Syntax highlighting | **MEDIUM** |
| 9 | persistence_layer.asm | 1,500 | Registry/JSON persistence | **MEDIUM** |
| 10 | qt6_file_browser.asm | 1,500 | File explorer panel | **MEDIUM** |

**Total Phase 3-4 New Files**: 10 files, ~13,200 MASM LOC

---

## TESTING CHECKLIST

### Dialog System Tests
- [ ] Create simple dialog window
- [ ] Display modal dialog successfully
- [ ] Modal dialog blocks parent input
- [ ] OK/Cancel buttons functional
- [ ] Dialog result returned correctly
- [ ] Dialog closes on button click
- [ ] Dialog cleans up memory on close

### Tab Control Tests
- [ ] Create tab control
- [ ] Add 3+ tabs
- [ ] Switch between tabs
- [ ] Tab selection notifications work
- [ ] Child windows hide/show correctly
- [ ] Tab titles display properly

### Settings Dialog Tests
- [ ] All 7 tabs visible
- [ ] Tab switching works
- [ ] Settings controls functional
- [ ] Settings saved to registry
- [ ] Settings loaded on startup
- [ ] OK/Cancel/Apply buttons work
- [ ] Validation prevents bad values

### File Browser Tests
- [ ] Directory tree displays
- [ ] File list shows files
- [ ] Selection works
- [ ] Double-click opens file
- [ ] Right-click context menu
- [ ] Filtering by file type

---

## SUCCESS CRITERIA FOR PHASE 3

By end of Phase 3 (target: 2 weeks):

✅ Dialog system fully functional  
✅ Tab control system operational  
✅ Settings dialog (7 tabs) complete  
✅ File browser with tree + list working  
✅ Theme system (light/dark) implemented  
✅ All controls compile without errors  
✅ 100% control functionality tested  
✅ All 10 new files passing compilation  

**Estimated MASM Code**: 13,000+ LOC  
**Estimated Object Files**: 10 .obj files  
**Estimated Total Size**: ~45-50 KB additional object code  

---

## RISK ASSESSMENT

### Low Risk
- Dialog system (well-documented Windows API)
- Tab control system (built-in comctl32 control)
- Registry persistence (straightforward Win32 API)

### Medium Risk
- Tree view implementation (more complex control)
- File browser integration (requires multiple controls working together)
- Theme system (color management across multiple components)

### Potential Blockers
- ⚠️ GDI text rendering for rich formatting (may need GDI+ or custom text layout)
- ⚠️ Common dialog library integration (GetOpenFileNameA can be finicky)
- ⚠️ Control notification routing (ensures messages reach right handlers)

**Mitigation**: Phase 2 patterns already established solid foundation, Phase 3 mostly "connecting pieces"

---

## COST-BENEFIT ANALYSIS

### Cost of Implementation
- **Developer Time**: 2-3 weeks (experienced MASM dev)
- **MASM LOC**: ~13,200 new lines
- **Object Code**: ~45-50 KB additional

### Benefit
- ✅ 80+ C++ files become replaceable with MASM
- ✅ Pure x64 native execution (no .NET runtime)
- ✅ ~25% of full IDE becomes pure MASM
- ✅ All settings, file operations, and UI configuration controllable from MASM

### ROI
**Very High** - These 10 files unblock 80+ C++ files, providing foundation for rest of conversion

---

## REMAINING QUESTIONS & DECISIONS

1. **Should we skip GPU compute for now?**
   - Recommendation: YES (too complex, can add later)
   - Impact: Inference falls back to CPU
   - Timeline saved: 4+ weeks

2. **Should we implement all tokenizers or just stub them?**
   - Recommendation: Stub for now, add later
   - Impact: Uses simple string matching instead of BPE
   - Timeline saved: 2-3 weeks

3. **Should training features be included?**
   - Recommendation: NO (inference-focused IDE, optional feature)
   - Impact: IDE can load/run models only (no fine-tuning)
   - Timeline saved: 2-3 weeks

4. **Should we target 100% C++ compatibility or MVP?**
   - Recommendation: MVP first (Phase 3-5), then additions
   - Impact: Faster delivery, can add features incrementally
   - Timeline: 2-3 months → Phase 3-5, 3-4 months → Full

---

## FINAL RECOMMENDATION

### PROCEED WITH PHASE 3 IMMEDIATELY

**Start**: Dialog System (dialog_system.asm) - Today/Tomorrow  
**Priority Path**: Dialog → Tab → ListViewControl → Settings Dialog  
**Timeline**: 2 weeks for full Phase 3-4 UI foundation  
**Outcome**: 80+ C++ files become replaceable, ~25% of IDE pure MASM  

**Next Milestone**: By Mid-January 2026
- ✅ Full settings UI operational
- ✅ File browser complete
- ✅ Theme system working
- ✅ Registry persistence functional
- ✅ 10+ new MASM components compiling
- ✅ Ready for Phase 5 (AI Chat, agentic features)

