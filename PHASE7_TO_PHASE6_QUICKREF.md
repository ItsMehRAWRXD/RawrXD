════════════════════════════════════════════════════════════════════════════════
PHASE 7 → PHASE 6 DEVELOPER QUICK REFERENCE
════════════════════════════════════════════════════════════════════════════════

PURPOSE
=======
This is a quick guide for Phase 6 (UI Polish) developers to understand what 
Phase 7 Batches 1 & 2 provide and how to use them to build the UI layer.

════════════════════════════════════════════════════════════════════════════════
QUANTIZATION CONTROLS API (Phase 7 Batch 2)
════════════════════════════════════════════════════════════════════════════════

Module: src/masm/final-ide/quantization_controls.asm

INITIALIZATION
==============
Call once at app startup:

    call QuantizationControls_Create
    ; Returns: RAX = pQuantizationState (or NULL if failed)
    ; Side Effect: Creates state, event, loads registry, refreshes hardware

POPULATE UI COMBO BOX
====================
After creating the quantization combo box (IDC_QUANT_COMBO), populate it:

    mov rcx, hComboBox  ; combo box HWND
    call QuantizationControls_PopulateComboBox
    ; Updates combo with 10 quantization types
    ; Sets current selection to last-applied

UPDATE VRAM DISPLAY
===================
In a timer callback (e.g., WM_TIMER every 1 second):

    mov rcx, hVRAMProgressBar  ; progress bar HWND
    mov rdx, hVRAMLabel        ; label HWND (for text)
    call QuantizationControls_UpdateVRAMDisplay
    ; Updates progress bar %, sets label to "X GB / Y GB Free"

APPLY QUANTIZATION
==================
When user clicks "Apply Quantization" button (IDC_APPLY_QUANT_BUTTON):

    ; Get selected quant type from combo
    mov rcx, hComboBox
    mov edx, CB_GETCURSEL
    call SendMessage  ; EAX = selected index (0-9)
    
    ; Apply it
    mov ecx, eax
    call QuantizationControls_ApplyQuantization
    ; Returns: RAX = TRUE (success) or FALSE (failed)
    ; Side Effects: Switches hardware quant, saves registry, fires event

AUTO-SELECT MODE
================
If user enables auto-select checkbox (IDC_AUTO_SELECT_CHECK):

    ; Get model size (in bytes)
    mov rcx, modelSizeInBytes
    call QuantizationControls_GetRecommendedQuantization
    ; Returns: EAX = recommended quant type (0-9)
    
    ; Auto-apply it
    mov ecx, eax
    call QuantizationControls_ApplyQuantization

LOADING MODEL PROFILE
====================
When user loads a .gguf model:

    mov rcx, pModelPath  ; wchar_t* full path
    call QuantizationControls_LoadModelProfile
    ; Returns: EAX = override quant type, or -1 (no override)
    ; Use return value to pre-select in combo if not -1

SAVING MODEL PROFILE
====================
When user wants to "Remember this quantization for this model":

    mov rcx, pModelPath  ; wchar_t* full path
    mov edx, selectedQuantType  ; 0-9
    call QuantizationControls_SaveModelProfile
    ; Returns: RAX = TRUE (saved) or FALSE (failed)

════════════════════════════════════════════════════════════════════════════════
PERFORMANCE DASHBOARD API (Phase 7 Batch 1)
════════════════════════════════════════════════════════════════════════════════

Module: src/masm/final-ide/performance_dashboard.asm (assumed compiled)

INITIALIZATION
==============
Call once at app startup (likely in same init as Quantization):

    call PerformanceDashboard_Create
    ; Returns: RAX = pDashboardState (or NULL if failed)
    ; Side Effect: Allocates buffers, creates percentile trackers

START MONITORING
================
After initialization:

    call PerformanceDashboard_StartMonitoring
    ; Returns: RAX = TRUE (started) or FALSE (failed)
    ; Side Effect: Creates SetTimer for metrics collection

RETRIEVE CURRENT STATS
======================
In UI update loop (e.g., WM_TIMER or WM_NOTIFY):

    LOCAL metrics:METRICS_SAMPLE
    
    lea rcx, metrics
    call PerformanceDashboard_GetCurrentStats
    ; Returns: RAX = TRUE (valid) or FALSE (no data)
    
    ; metrics now contains:
    ;   TokensPerSecond, TokenLatencyMs, CpuUsagePercent, GpuUsagePercent

DISPLAY METRICS
===============
After GetCurrentStats:

    ; Update labels on UI
    mov rax, metrics.TokensPerSecond
    ; Format as "8,259 TPS" and display
    
    mov rax, metrics.TokenLatencyMs
    ; Format as "0.32 ms" and display
    
    mov rax, metrics.CpuUsagePercent
    ; Format as "45.2%" and display
    
    mov rax, metrics.GpuUsagePercent
    ; Format as "78.1%" and display

EXPORT DATA
===========
When user clicks "Export Metrics..." button:

    mov rcx, pExportFilePath  ; wchar_t* (e.g., "metrics.csv")
    call PerformanceDashboard_ExportData
    ; Returns: RAX = TRUE (exported) or FALSE (failed)
    ; Writes CSV: Timestamp,TPS,Latency,CPU%,GPU%

STOP MONITORING
===============
At app shutdown:

    call PerformanceDashboard_StopMonitoring
    ; Returns: RAX = TRUE (stopped) or FALSE (not running)
    ; Side Effect: KillTimer, stops collection

════════════════════════════════════════════════════════════════════════════════
NOTIFICATION STUB
════════════════════════════════════════════════════════════════════════════════

Module: src/masm/final-ide/performance_dashboard_stub.asm

PUBLIC API: PerformanceDashboard_NotifyConfigChange

Called automatically by Batch 2 when quantization changes:

    mov ecx, PERF_CHANGE_QUANTIZATION  ; 1 = quantization change
    mov edx, newQuantType               ; 0-9
    call PerformanceDashboard_NotifyConfigChange

Currently a stub (does nothing). Phase 6 should enhance to:
    • Reset dashboard statistics
    • Update quantization-specific speed factors
    • Refresh GPU metrics for new quant overhead

════════════════════════════════════════════════════════════════════════════════
CONTROL ID MAPPING
════════════════════════════════════════════════════════════════════════════════

QUANTIZATION TAB (IDC_QUANT_TAB, tab index 7):

    IDC_QUANT_COMBO         = 3101  (ComboBox for quant type selection)
    IDC_VRAM_LABEL          = 3102  (Label for VRAM text, "X GB / Y GB")
    IDC_CURRENT_QUANT_LABEL = 3104  (Label for current quantization name)
    IDC_APPLY_QUANT_BUTTON  = 3105  (Button to apply selected quant)
    IDC_AUTO_SELECT_CHECK   = 3106  (Checkbox for auto-select mode)
    IDC_VRAM_PROGRESS       = 3107  (Progress bar for VRAM utilization)

PERFORMANCE DASHBOARD TAB (pending Phase 6):

    IDC_METRICS_GRAPH       = 3001  (Graph/chart for TPS, latency)
    IDC_TPS_LABEL           = 3002  (Label for "X TPS")
    IDC_LATENCY_LABEL       = 3003  (Label for "X ms")
    IDC_CPU_USAGE_LABEL     = 3004  (Label for "X%")
    IDC_GPU_USAGE_LABEL     = 3005  (Label for "X%")
    IDC_RESET_BUTTON        = 3006  (Button to clear metrics)
    IDC_EXPORT_BUTTON       = 3007  (Button to export CSV)

════════════════════════════════════════════════════════════════════════════════
REGISTRY KEYS
════════════════════════════════════════════════════════════════════════════════

QUANTIZATION (read/written by Batch 2 APIs):

    HKCU\Software\RawrXD\Quantization\DefaultQuantization     (DWORD)
    HKCU\Software\RawrXD\Quantization\AutoSelectEnabled       (DWORD, 0/1)
    HKCU\Software\RawrXD\Quantization\LastAppliedQuantization (DWORD)
    HKCU\Software\RawrXD\Quantization\ModelProfile_<HASH>    (DWORD per-model)

PERFORMANCE (read/written by Batch 1 APIs):

    HKCU\Software\RawrXD\Performance\DashboardEnabled        (DWORD, 0/1)
    HKCU\Software\RawrXD\Performance\UpdateInterval          (DWORD, milliseconds)
    HKCU\Software\RawrXD\Performance\MaxHistorySamples       (DWORD)
    HKCU\Software\RawrXD\Performance\MetricsMask             (DWORD, bitmask)

You DON'T need to manage these directly; the APIs handle it.

════════════════════════════════════════════════════════════════════════════════
COMMON PHASE 6 TASKS
════════════════════════════════════════════════════════════════════════════════

TASK 1: Build a Real-Time Metrics Display
==========================================
1. Create a timer (WM_TIMER or SetTimer with 1000ms interval)
2. In timer callback:
   a. Call PerformanceDashboard_GetCurrentStats
   b. Update label controls with TPS, latency, CPU%, GPU%
3. Optional: Build a D3D11 graph control to show last 100 samples

TASK 2: Add Quick-Quantization Buttons
=======================================
1. Create 5 buttons: "Q2_K", "Q4_0", "Q4_K", "Q6_K", "F32"
2. In each button's click handler:
   a. Determine quant type (0-9)
   b. Call QuantizationControls_ApplyQuantization with type
   c. Show progress dialog (SetWindowText "Applying Q4_K...")
   d. Wait for PerformanceDashboard_NotifyConfigChange callback
   e. Update combo and stats labels

TASK 3: Implement Auto-Select with Feedback
============================================
1. On IDC_AUTO_SELECT_CHECK state change:
   a. Call QuantizationControls_GetRecommendedQuantization with model size
   b. Populate combo with recommendation (e.g., "Q5_K - Recommended")
   c. Optional: Show tooltip "Q5_K recommended for 8GB VRAM, 7B model"
2. If user clicks "Apply", auto-apply the recommended type

TASK 4: Add Import/Export Buttons
==================================
1. "Export Metrics" button calls PerformanceDashboard_ExportData
   → Opens file dialog, saves to metrics.csv
2. "Save Quantization Profile" button
   → Saves current model path + quant type via 
     QuantizationControls_SaveModelProfile

TASK 5: Polish with Visual Feedback
====================================
1. During quantization apply:
   a. Disable combo + apply button (SetWindowLongPtr disable style)
   b. Show progress text "Switching to Q4_K..."
   c. Re-enable after PerformanceDashboard_NotifyConfigChange fires
2. VRAM progress bar:
   a. Red if < 20% free
   b. Yellow if 20-50% free
   c. Green if > 50% free
3. Metrics labels:
   a. Bold red if CPU/GPU > 90%
   b. Normal if < 70%
   c. Amber if 70-90%

════════════════════════════════════════════════════════════════════════════════
ERROR HANDLING PATTERNS
════════════════════════════════════════════════════════════════════════════════

All Phase 7 APIs return success/failure indicators:

    call QuantizationControls_ApplyQuantization
    test rax, rax
    jz handle_error
    ; Success: RAX = TRUE
    jmp continue
    
handle_error:
    ; Failure: RAX = FALSE or 0
    mov rcx, OFFSET szError
    call MessageBoxA
    ret

════════════════════════════════════════════════════════════════════════════════
DEBUGGING TIPS
════════════════════════════════════════════════════════════════════════════════

1. Check Registry Values:
   regedit → HKCU\Software\RawrXD\Quantization
   Verify DefaultQuantization, LastAppliedQuantization are saved

2. Monitor SetTimer Callback:
   Insert OutputDebugString in WM_TIMER to confirm metrics loop running

3. Verify VRAM Detection:
   QuantizationControls_GetRecommendedQuantization should return
   a type based on available VRAM + model size

4. Test Quantization Switch:
   Check Windows Event Viewer (Kernel Logging) for device state changes
   during HardwareAccelerator_SwitchQuantization call

5. Memory Validation:
   Use DrMemory or Valgrind to check for leaks after running through
   all Phase 7 APIs at least once

════════════════════════════════════════════════════════════════════════════════
END OF QUICK REFERENCE
════════════════════════════════════════════════════════════════════════════════
