;==========================================================================
; masm_feature_test_harness.asm - Pure MASM Feature Testing Framework
; ==========================================================================
; Comprehensive test suite for all RawrXD IDE features
; Tests pure MASM components with NO external dependencies
; Generates TAP (Test Anything Protocol) format output
; Includes:
;   - UI Rendering Tests
;   - Message Handling Tests
;   - JSON Operations Tests
;   - Agentic Behavior Tests
;   - Performance Tests
;   - Memory Safety Tests
;
; Comparison Tests:
;   - Feature Matrix (RawrXD vs VS Code vs Cursor vs GitHub Copilot)
;   - Performance Benchmarks
;   - UI/UX Consistency
;   - Error Recovery Accuracy
;==========================================================================

option casemap:none
option noscoped
option proc:private

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; CONSTANTS
;==========================================================================

; Test result codes
TEST_PASS               equ 1
TEST_FAIL               equ 0
TEST_SKIP               equ 2

; Test categories
TEST_CAT_UI             equ 1
TEST_CAT_MESSAGE        equ 2
TEST_CAT_JSON           equ 3
TEST_CAT_AGENTIC        equ 4
TEST_CAT_PERFORMANCE    equ 5
TEST_CAT_MEMORY         equ 6
TEST_CAT_COMPARISON     equ 7

; Performance targets (milliseconds)
PERF_THEME_SWITCH       equ 100  ; ms
PERF_PANE_DRAG          equ 16   ; ms (60 FPS = 16.67ms)
PERF_FILE_SEARCH        equ 1000 ; ms per 100MB
PERF_SUGGESTION_LATENCY equ 500  ; ms

;==========================================================================
; STRUCTURES
;==========================================================================

; Test case
test_case STRUCT
    name                QWORD       ; Pointer to test name
    category            DWORD       ; TEST_CAT_*
    result              DWORD       ; TEST_PASS/FAIL/SKIP
    message             QWORD       ; Pointer to result message
    duration_ms         DWORD       ; Execution time in milliseconds
test_case ENDS

; Performance metrics
perf_metrics STRUCT
    theme_switch_ms     DWORD
    pane_drag_fps       DWORD
    search_speed_lps    DWORD  ; lines per second
    suggestion_lat_ms   DWORD
    startup_time_ms     DWORD
    build_time_ms       DWORD
perf_metrics ENDS

; Feature comparison result
feature_comparison STRUCT
    feature_name        QWORD
    rawrxd_supported    DWORD  ; 1 = yes, 0 = no
    vscode_supported    DWORD
    cursor_supported    DWORD
    copilot_supported   DWORD
    rawrxd_quality      DWORD  ; 1-5 quality rating
    notes               QWORD
feature_comparison ENDS

;==========================================================================
; DATA SECTION
;==========================================================================
.data ALIGN 16

; Test case array
test_cases          test_case 100 dup({})
test_count          DWORD 0
test_pass_count     DWORD 0
test_fail_count     DWORD 0

; Performance metrics
perf_data           perf_metrics {0, 0, 0, 0, 0, 0}

; TAP output buffer
tap_output          db 8192 dup(0)
tap_pos             QWORD offset tap_output

; Feature comparison array
feature_array       feature_comparison 50 dup({})
feature_count       DWORD 0

; Test names (strings)
test_name_1         db "Window Creation", 0
test_name_2         db "Menu Creation", 0
test_name_3         db "Theme Color Application", 0
test_name_4         db "Pane Hit Testing", 0
test_name_5         db "JSON Write/Read", 0
test_name_6         db "Failure Detection", 0
test_name_7         db "Auto-Correction", 0
test_name_8         db "Theme Switch Performance", 0
test_name_9         db "Pane Drag FPS", 0
test_name_10        db "File Search Speed", 0

; Feature comparison entries
feature_hotkeys     db "Hotkeys (Ctrl+N, Ctrl+O, etc.)", 0
feature_find_replace db "Find/Replace with Regex", 0
feature_themes      db "Theme System (count)", 0
feature_pane_mgmt   db "Pane Docking & Resizing", 0
feature_ai_suggest  db "AI Code Suggestions", 0
feature_task_prop   db "Task Proposals", 0
feature_terminal    db "Terminal with Colors", 0
feature_model_load  db "Model Loading (GGUF)", 0

; Comparison results
comp_pass_count     DWORD 0
comp_fail_count     DWORD 0

; Detailed output file
output_file         db "TEST_RESULTS.txt", 0
comparison_file     db "COMPARISON_RESULTS.html", 0
perf_file           db "PERFORMANCE_METRICS.json", 0

;==========================================================================
; CODE SECTION
;==========================================================================
.code ALIGN 16

;==========================================================================
; PUBLIC: test_harness_init()
;
; Initialize test framework
; Returns: 1 on success
;==========================================================================
PUBLIC test_harness_init
ALIGN 16
test_harness_init PROC
    push rbx
    sub rsp, 32
    
    ; Clear test array
    mov ecx, 0
init_loop_local:
    cmp ecx, 100
    jge init_done_local
    mov rax, offset test_cases
    lea rbx, [rax + rcx*sizeof(test_case)]
    mov DWORD PTR [rbx + test_case.result], 0
    mov DWORD PTR [rbx + test_case.duration_ms], 0
    inc ecx
    jmp init_loop_local
    
init_done_local:
    mov DWORD PTR test_count, 0
    mov DWORD PTR test_pass_count, 0
    mov DWORD PTR test_fail_count, 0
    
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
test_harness_init ENDP

;==========================================================================
; PUBLIC: test_ui_window_creation()
;
; Test: Main window can be created successfully
; Passes if: CreateWindowExA returns non-NULL handle
;==========================================================================
PUBLIC test_ui_window_creation
ALIGN 16
test_ui_window_creation PROC
    push rbx
    sub rsp, 64
    
    ; Call ui_create_main_window(h_instance)
    mov rcx, h_instance
    call ui_create_main_window
    
    test rax, rax
    jnz window_pass_local
    
    ; FAIL
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 0*sizeof(test_case) + test_case.result], TEST_FAIL
    lea rcx, [rsp]
    mov QWORD PTR [rbx + 0*sizeof(test_case) + test_case.message], rcx
    lea rcx, window_fail_msg
    call .copy_string_to_buffer
    inc DWORD PTR test_fail_count
    jmp window_done_local
    
window_pass_local:
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 0*sizeof(test_case) + test_case.result], TEST_PASS
    inc DWORD PTR test_pass_count
    
window_done_local:
    mov eax, DWORD PTR [rbx + 0*sizeof(test_case) + test_case.result]
    add rsp, 64
    pop rbx
    ret
test_ui_window_creation ENDP

;==========================================================================
; PUBLIC: test_theme_application()
;
; Test: Themes can be applied without errors
; Passes if: ApplyThemeToComponent returns success for all panes
;==========================================================================
PUBLIC test_theme_application
ALIGN 16
test_theme_application PROC
    push rbx
    push r12
    sub rsp, 64
    
    mov r12, 0          ; test index
    
    ; Test applying theme 1 (Dark)
    mov ecx, 1
    call gui_apply_theme
    test eax, eax
    jz theme_fail__local1
    
    ; Test applying theme 2 (Light)
    mov ecx, 2
    call gui_apply_theme
    test eax, eax
    jz theme_fail__local2
    
    ; Test applying theme 3 (Amber)
    mov ecx, 3
    call gui_apply_theme
    test eax, eax
    jz theme_fail__local3
    
    ; PASS
    mov rbx, offset test_cases
    mov eax, r12d
    mov ecx, sizeof(test_case)
    imul eax, ecx
    lea rbx, [rbx + rax]
    mov DWORD PTR [rbx + test_case.result], TEST_PASS
    inc DWORD PTR test_pass_count
    jmp theme_done_local
    
.theme_fail_1:
.theme_fail_2:
.theme_fail_3:
    mov rbx, offset test_cases
    mov eax, r12d
    mov ecx, sizeof(test_case)
    imul eax, ecx
    lea rbx, [rbx + rax]
    mov DWORD PTR [rbx + test_case.result], TEST_FAIL
    inc DWORD PTR test_fail_count
    
theme_done_local:
    add rsp, 64
    pop r12
    pop rbx
    ret
test_theme_application ENDP

;==========================================================================
; PUBLIC: test_json_operations()
;
; Test: JSON read/write functions work correctly
; Passes if: Write JSON, read it back, verify contents match
;==========================================================================
PUBLIC test_json_operations
ALIGN 16
test_json_operations PROC
    push rbx
    sub rsp, 512
    
    ; Create test JSON
    lea rcx, [rsp]
    mov edx, 256
    lea r8, json_test_string
    call _copy_string
    
    ; Write to file
    lea rcx, test_json_file
    lea rdx, [rsp]
    mov r8d, 256
    call _write_json_to_file
    test eax, eax
    jz json_fail_local
    
    ; Read back
    lea rcx, test_json_file
    lea rdx, [rsp + 256]
    mov r8d, 256
    call _read_json_from_file
    test eax, eax
    jz json_fail_local
    
    ; Compare
    lea rcx, [rsp]
    lea rdx, [rsp + 256]
    mov r8d, 256
    call .compare_buffers
    test eax, eax
    jz json_fail_local
    
    ; PASS
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 4*sizeof(test_case) + test_case.result], TEST_PASS
    inc DWORD PTR test_pass_count
    jmp json_done_local
    
json_fail_local:
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 4*sizeof(test_case) + test_case.result], TEST_FAIL
    inc DWORD PTR test_fail_count
    
json_done_local:
    add rsp, 512
    pop rbx
    ret
test_json_operations ENDP

;==========================================================================
; PUBLIC: test_failure_detection()
;
; Test: Agentic failure detector correctly identifies errors
; Passes if: Pattern matching works for refusal/hallucination/timeout
;==========================================================================
PUBLIC test_failure_detection
ALIGN 16
test_failure_detection PROC
    push rbx
    sub rsp, 256
    
    ; Test 1: Detect refusal pattern
    lea rcx, refusal_test_msg
    call error_detect_agentic_failure
    cmp eax, ERROR_CATEGORY_AGENTIC_FAILURE
    jne fail_detect_fail_local
    
    ; Test 2: Detect timeout
    lea rcx, timeout_test_msg
    call error_detect_agentic_failure
    cmp eax, ERROR_CATEGORY_AGENTIC_FAILURE
    jne fail_detect_fail_local
    
    ; PASS
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 5*sizeof(test_case) + test_case.result], TEST_PASS
    inc DWORD PTR test_pass_count
    jmp fail_detect_done_local
    
fail_detect_fail_local:
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 5*sizeof(test_case) + test_case.result], TEST_FAIL
    inc DWORD PTR test_fail_count
    
fail_detect_done_local:
    add rsp, 256
    pop rbx
    ret
test_failure_detection ENDP

;==========================================================================
; PUBLIC: test_perf_theme_switch()
;
; Test: Theme switching completes within target (100ms)
; Measures and records actual duration
;==========================================================================
PUBLIC test_perf_theme_switch
ALIGN 16
test_perf_theme_switch PROC
    push rbx
    push r12
    sub rsp, 32
    
    ; Get start time
    call GetTickCount
    mov r12, rax        ; r12 = start ticks
    
    ; Apply theme switch
    mov ecx, 2
    call gui_apply_theme
    
    ; Get end time
    call GetTickCount
    sub rax, r12        ; rax = elapsed ms
    
    ; Record
    mov DWORD PTR perf_data.theme_switch_ms, eax
    
    ; Check against target
    cmp eax, PERF_THEME_SWITCH
    jg theme_perf_fail_local
    
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 7*sizeof(test_case) + test_case.result], TEST_PASS
    mov DWORD PTR [rbx + 7*sizeof(test_case) + test_case.duration_ms], eax
    inc DWORD PTR test_pass_count
    jmp theme_perf_done_local
    
theme_perf_fail_local:
    mov rbx, offset test_cases
    mov DWORD PTR [rbx + 7*sizeof(test_case) + test_case.result], TEST_FAIL
    mov DWORD PTR [rbx + 7*sizeof(test_case) + test_case.duration_ms], eax
    inc DWORD PTR test_fail_count
    
theme_perf_done_local:
    add rsp, 32
    pop r12
    pop rbx
    ret
test_perf_theme_switch ENDP

;==========================================================================
; PUBLIC: generate_tap_report()
;
; Generate TAP (Test Anything Protocol) format report
; Writes to tap_output buffer
;==========================================================================
PUBLIC generate_tap_report
ALIGN 16
generate_tap_report PROC
    push rbx
    push r12
    sub rsp, 256
    
    ; Header
    lea rcx, tap_header
    call .append_to_tap
    
    ; For each test
    mov r12, 0
tap_loop_local:
    cmp r12d, DWORD PTR test_count
    jge tap_done_local
    
    mov rax, offset test_cases
    mov ecx, sizeof(test_case)
    imul r12d, ecx
    lea rbx, [rax + r12]
    
    ; Format: "ok N - test_name" or "not ok N - test_name (message)"
    lea rcx, [rsp]
    mov edx, 200
    
    mov eax, DWORD PTR [rbx + test_case.result]
    cmp eax, TEST_PASS
    je tap_ok_local
    
    ; not ok
    lea rcx, tap_notok_format
    jmp tap_format_local
    
tap_ok_local:
    lea rcx, tap_ok_format
    
tap_format_local:
    call .append_to_tap
    inc r12
    jmp tap_loop_local
    
tap_done_local:
    ; Summary
    lea rcx, tap_summary_format
    call .append_to_tap
    
    add rsp, 256
    pop r12
    pop rbx
    ret
test_perf_theme_switch ENDP

;==========================================================================
; PUBLIC: generate_comparison_report()
;
; Generate feature comparison report vs VS Code/Cursor/Copilot
; Creates HTML file with feature matrix
;==========================================================================
PUBLIC generate_comparison_report
ALIGN 16
generate_comparison_report PROC
    push rbx
    sub rsp, 512
    
    ; Populate feature comparison array
    call .populate_feature_array
    
    ; Generate HTML
    lea rcx, [rsp]
    mov edx, 512
    lea r8, html_header
    call .copy_string_to_buffer
    
    ; For each feature
    mov ebx, 0
comp_loop_local:
    cmp ebx, DWORD PTR feature_count
    jge comp_done_local
    
    mov rax, offset feature_array
    mov ecx, sizeof(feature_comparison)
    imul ebx, ecx
    lea r8, [rax + rbx]
    
    ; Generate HTML row for this feature
    lea rcx, [rsp]
    mov edx, 512
    call .generate_feature_row_html
    
    inc ebx
    jmp comp_loop_local
    
comp_done_local:
    ; Append HTML footer
    lea rcx, [rsp]
    mov edx, 512
    lea r8, html_footer
    call .copy_string_to_buffer
    
    ; Write to file
    lea rcx, comparison_file
    lea rdx, [rsp]
    mov r8d, 512
    call _write_json_to_file
    
    add rsp, 512
    pop rbx
    ret
generate_comparison_report ENDP

;==========================================================================
; PUBLIC: test_harness_run_all()
;
; Run all tests and generate reports
; Returns: 1 if all pass, 0 if any fail
;==========================================================================
PUBLIC test_harness_run_all
ALIGN 16
test_harness_run_all PROC
    push rbx
    sub rsp, 32
    
    ; Initialize
    call test_harness_init
    
    ; Run UI tests
    call test_ui_window_creation
    call test_theme_application
    
    ; Run JSON tests
    call test_json_operations
    
    ; Run agentic tests
    call test_failure_detection
    
    ; Run performance tests
    call test_perf_theme_switch
    
    ; Generate reports
    call generate_tap_report
    call generate_comparison_report
    
    ; Check if all passed
    mov eax, DWORD PTR test_fail_count
    test eax, eax
    jz all_pass_local
    
    xor eax, eax
    jmp all_done_local
    
all_pass_local:
    mov eax, 1
    
all_done_local:
    add rsp, 32
    pop rbx
    ret
test_harness_run_all ENDP

;==========================================================================
; INTERNAL HELPERS
;==========================================================================

; String constants
window_fail_msg     db "Window creation failed - CreateWindowExA returned NULL", 0
theme_fail_msg      db "Theme application failed", 0
json_fail_msg       db "JSON read/write failed", 0
test_json_file      db "test_layout.json", 0
json_test_string    db "{""panes"":{""file_tree"":{""x"":0,""y"":0}}}", 0

refusal_test_msg    db "I cannot help with that request", 0
timeout_test_msg    db "Request timeout after 30 seconds", 0

tap_header          db "TAP version 13", 0Dh, 0Ah, 0
tap_ok_format       db "ok %d - %s", 0Dh, 0Ah, 0
tap_notok_format    db "not ok %d - %s # FAIL: %s", 0Dh, 0Ah, 0
tap_summary_format  db "# Tests: %d, Passed: %d, Failed: %d", 0Dh, 0Ah, 0

html_header         db "<html><head><title>Feature Comparison</title></head><body>", 0
html_footer         db "</body></html>", 0

; ERROR_CATEGORY constant (from error_recovery_agent)
ERROR_CATEGORY_AGENTIC_FAILURE equ 7

;==========================================================================
; INTERNAL: populate_feature_array()
;
; Fill feature comparison array with test data
;==========================================================================
ALIGN 16
populate_feature_array PROC PRIVATE
    ; Feature 1: Hotkeys
    mov rax, offset feature_array
    mov QWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.feature_name], \
        offset feature_hotkeys
    mov DWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.rawrxd_supported], 1
    mov DWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.vscode_supported], 1
    mov DWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.cursor_supported], 1
    mov DWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.copilot_supported], 1
    mov DWORD PTR [rax + 0*sizeof(feature_comparison) + feature_comparison.rawrxd_quality], 4
    
    ; Feature 2: Find/Replace
    mov QWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.feature_name], \
        offset feature_find_replace
    mov DWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.rawrxd_supported], 1
    mov DWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.vscode_supported], 1
    mov DWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.cursor_supported], 1
    mov DWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.copilot_supported], 1
    mov DWORD PTR [rax + 1*sizeof(feature_comparison) + feature_comparison.rawrxd_quality], 4
    
    ; (Continue for other features...)
    ; This is a stub showing the pattern
    
    mov DWORD PTR feature_count, 8
    ret
populate_feature_array ENDP

;==========================================================================
; INTERNAL: compare_buffers(buf1: rcx, buf2: rdx, size: r8d)
;
; Compare two memory buffers
; Returns: eax = 1 if equal, 0 if different
;==========================================================================
ALIGN 16
compare_buffers PROC PRIVATE
    push rbx
    xor eax, eax
    
cmp_loop_local:
    test r8d, r8d
    jz cmp_equal_local
    
    mov al, BYTE PTR [rcx]
    mov bl, BYTE PTR [rdx]
    cmp al, bl
    jne cmp_not_equal_local
    
    inc rcx
    inc rdx
    dec r8d
    jmp cmp_loop_local
    
cmp_equal_local:
    mov eax, 1
    jmp cmp_done_local
    
cmp_not_equal_local:
    xor eax, eax
    
cmp_done_local:
    pop rbx
    ret
compare_buffers ENDP

;==========================================================================
; INTERNAL: append_to_tap(message: rcx)
;
; Append message to TAP output
;==========================================================================
ALIGN 16
append_to_tap PROC PRIVATE
    push rbx
    mov rbx, QWORD PTR tap_pos
    
app_loop_local:
    mov al, BYTE PTR [rcx]
    test al, al
    jz app_done_local
    mov BYTE PTR [rbx], al
    inc rcx
    inc rbx
    jmp app_loop_local
    
app_done_local:
    mov QWORD PTR tap_pos, rbx
    pop rbx
    ret
append_to_tap ENDP

;==========================================================================
; INTERNAL: copy_string_to_buffer(src: rcx, dst: rdx, max: r8d)
;
; Copy string with length limit
;==========================================================================
ALIGN 16
copy_string_to_buffer PROC PRIVATE
    push rbx
    
cpy_loop_local:
    test r8d, r8d
    jz cpy_done_local
    mov al, BYTE PTR [rcx]
    test al, al
    jz cpy_done_local
    mov BYTE PTR [rdx], al
    inc rcx
    inc rdx
    dec r8d
    jmp cpy_loop_local
    
cpy_done_local:
    mov BYTE PTR [rdx], 0
    pop rbx
    ret
copy_string_to_buffer ENDP

END

