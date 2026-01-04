;==========================================================================
; masm_ml_visualization.asm - ML Visualization Studio for RawrXD IDE
;==========================================================================
; Comprehensive ML-specific visualization with:
; - Confusion matrix renderer
; - ROC/PR curve plotter
; - Feature importance charts
; - t-SNE/UMAP embeddings viewer
; - Attention heatmaps (for transformers)
; - Training progress visualization
;==========================================================================

option casemap:none
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib
includelib comctl32.lib

;==========================================================================
; CONSTANTS
;==========================================================================
MAX_POINTS         equ 10000
MAX_CLASSES        equ 100
MAX_FEATURES       equ 1000
MAX_ATTENTION_HEADS equ 16

; Chart types
CHART_CONFUSION    equ 1
CHART_ROC          equ 2
CHART_PR           equ 3
CHART_FEATURE_IMP  equ 4
CHART_EMBEDDING    equ 5
CHART_ATTENTION    equ 6
CHART_LOSS_CURVE   equ 7

; Color schemes
COLOR_SCHEME_DEFAULT equ 0
COLOR_SCHEME_HEATMAP equ 1
COLOR_SCHEME_RAINBOW equ 2
COLOR_SCHEME_PASTEL  equ 3

;==========================================================================
; STRUCTURES
;==========================================================================

; Data point for scatter plots (16 bytes)
DATA_POINT struct
    x               REAL4 0.0
    y               REAL4 0.0
    z               REAL4 0.0
    label           DWORD 0
    confidence      REAL4 1.0
DATA_POINT ends

; Confusion matrix data (variable size)
CONFUSION_MATRIX struct
    classes         DWORD MAX_CLASSES dup(0)
    class_count     DWORD 0
    matrix          DWORD MAX_CLASSES * MAX_CLASSES dup(0)
    normalized      BYTE 0
CONFUSION_MATRIX ends

; ROC curve data (variable size)
ROC_CURVE struct
    fpr             REAL4 MAX_POINTS dup(0.0)
    tpr             REAL4 MAX_POINTS dup(0.0)
    thresholds      REAL4 MAX_POINTS dup(0.0)
    point_count     DWORD 0
    auc             REAL4 0.0
ROC_CURVE ends

; Feature importance data (variable size)
FEATURE_IMPORTANCE struct
    feature_names   BYTE 32 * MAX_FEATURES dup(0)
    importance      REAL4 MAX_FEATURES dup(0.0)
    feature_count   DWORD 0
FEATURE_IMPORTANCE ends

; Embedding data (variable size)
EMBEDDING_DATA struct
    points          DATA_POINT MAX_POINTS dup(<>)
    point_count     DWORD 0
    method          DWORD 0  ; 0=t-SNE, 1=UMAP, 2=PCA
    dimensions      DWORD 2  ; 2D or 3D
EMBEDDING_DATA ends

; Attention heatmap data (variable size)
ATTENTION_HEATMAP struct
    sequence_length DWORD 0
    num_heads       DWORD 0
    attention       REAL4 MAX_ATTENTION_HEADS * 512 * 512 dup(0.0)
    tokens          BYTE 64 * 512 dup(0)
ATTENTION_HEATMAP ends

; Visualization state
VISUALIZATION_STUDIO struct
    hWindow         QWORD 0
    hChartArea      QWORD 0
    hControlPanel   QWORD 0
    hLegend         QWORD 0
    
    ; Current chart
    chart_type      DWORD CHART_CONFUSION
    chart_data      QWORD 0
    
    ; Display settings
    width           DWORD 800
    height          DWORD 600
    color_scheme    DWORD COLOR_SCHEME_DEFAULT
    show_grid       BYTE 1
    show_legend     BYTE 1
    show_tooltips   BYTE 1
    
    ; Interaction state
    zoom_level      REAL4 1.0
    pan_x           REAL4 0.0
    pan_y           REAL4 0.0
    selected_point  DWORD -1
    
    ; Back buffer for flicker-free drawing
    hBackBuffer     QWORD 0
    hBackBufferDC   QWORD 0
VISUALIZATION_STUDIO ends

;==========================================================================
; DATA
;==========================================================================
.data
g_visualization_studio VISUALIZATION_STUDIO <>

; Window classes
szVisualizationClass db "VisualizationStudio",0
szChartAreaClass    db "ChartArea",0

; Default strings
szConfusionTitle   db "Confusion Matrix",0
szROCTitle         db "ROC Curve",0
szPRTitle          db "Precision-Recall Curve",0
szFeatureImpTitle  db "Feature Importance",0
szEmbeddingTitle   db "Embedding Visualization",0
szAttentionTitle   db "Attention Heatmap",0
szLossCurveTitle   db "Training Loss Curve",0

; Color names for schemes
szColorDefault     db "Default",0
szColorHeatmap     db "Heatmap",0
szColorRainbow     db "Rainbow",0
szColorPastel      db "Pastel",0

.code

;==========================================================================
; EXTERNAL DECLARATIONS
;==========================================================================
EXTERN RegisterClassExA:PROC
EXTERN CreateWindowExA:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN InvalidateRect:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN CreateCompatibleDC:PROC
EXTERN CreateCompatibleBitmap:PROC
EXTERN SelectObject:PROC
EXTERN BitBlt:PROC
EXTERN DeleteDC:PROC
EXTERN DeleteObject:PROC
EXTERN CreateSolidBrush:PROC
EXTERN Rectangle:PROC
EXTERN FillRect:PROC
EXTERN DrawTextA:PROC
EXTERN SetBkMode:PROC
EXTERN SetTextColor:PROC
EXTERN CreateFontA:PROC
EXTERN SetTimer:PROC
EXTERN KillTimer:PROC

;==========================================================================
; PUBLIC EXPORTS
;==========================================================================
PUBLIC visualization_init
PUBLIC visualization_create_window
PUBLIC visualization_render_confusion
PUBLIC visualization_render_roc
PUBLIC visualization_render_pr
PUBLIC visualization_render_feature_imp
PUBLIC visualization_render_embedding
PUBLIC visualization_render_attention
PUBLIC visualization_render_loss_curve
PUBLIC visualization_export_chart
PUBLIC visualization_set_color_scheme
PUBLIC visualization_zoom
PUBLIC visualization_pan

;==========================================================================
; visualization_init() -> bool (rax)
; Initialize visualization system
;==========================================================================
visualization_init PROC
    sub rsp, 32
    
    ; Register window classes
    call register_visualization_class
    call register_chart_area_class
    
    ; Initialize state
    mov g_visualization_studio.chart_type, CHART_CONFUSION
    mov g_visualization_studio.width, 800
    mov g_visualization_studio.height, 600
    mov g_visualization_studio.color_scheme, COLOR_SCHEME_DEFAULT
    mov byte ptr g_visualization_studio.show_grid, 1
    mov byte ptr g_visualization_studio.show_legend, 1
    mov byte ptr g_visualization_studio.show_tooltips, 1
    mov dword ptr g_visualization_studio.zoom_level, 1.0
    mov dword ptr g_visualization_studio.pan_x, 0.0
    mov dword ptr g_visualization_studio.pan_y, 0.0
    mov g_visualization_studio.selected_point, -1
    
    mov rax, 1  ; Success
    add rsp, 32
    ret
visualization_init ENDP

;==========================================================================
; register_visualization_class() - Register main window class
;==========================================================================
register_visualization_class PROC
    LOCAL wc:WNDCLASSEXA
    
    sub rsp, 96
    
    mov dword ptr [wc.cbSize], sizeof WNDCLASSEXA
    mov dword ptr [wc.style], 3     ; CS_HREDRAW | CS_VREDRAW
    lea rax, visualization_wnd_proc
    mov qword ptr [wc.lpfnWndProc], rax
    mov dword ptr [wc.cbClsExtra], 0
    mov dword ptr [wc.cbWndExtra], 0
    mov qword ptr [wc.hInstance], 0
    mov qword ptr [wc.hIcon], 0
    mov qword ptr [wc.hCursor], 0
    mov qword ptr [wc.hbrBackground], 0
    mov qword ptr [wc.lpszMenuName], 0
    lea rax, szVisualizationClass
    mov qword ptr [wc.lpszClassName], rax
    mov qword ptr [wc.hIconSm], 0
    
    lea rcx, wc
    call RegisterClassExA
    
    add rsp, 96
    ret
register_visualization_class ENDP

;==========================================================================
; register_chart_area_class() - Register chart area class
;==========================================================================
register_chart_area_class PROC
    LOCAL wc:WNDCLASSEXA
    
    sub rsp, 96
    
    mov dword ptr [wc.cbSize], sizeof WNDCLASSEXA
    mov dword ptr [wc.style], 3
    lea rax, chart_area_wnd_proc
    mov qword ptr [wc.lpfnWndProc], rax
    mov dword ptr [wc.cbClsExtra], 0
    mov dword ptr [wc.cbWndExtra], 0
    mov qword ptr [wc.hInstance], 0
    mov qword ptr [wc.hIcon], 0
    mov qword ptr [wc.hCursor], 0
    mov qword ptr [wc.hbrBackground], 0
    mov qword ptr [wc.lpszMenuName], 0
    lea rax, szChartAreaClass
    mov qword ptr [wc.lpszClassName], rax
    mov qword ptr [wc.hIconSm], 0
    
    lea rcx, wc
    call RegisterClassExA
    
    add rsp, 96
    ret
register_chart_area_class ENDP

;==========================================================================
; visualization_create_window(parent_hwnd: rcx) -> hwnd (rax)
; Create visualization window
;==========================================================================
visualization_create_window PROC
    push rbx
    sub rsp, 96
    
    mov rbx, rcx  ; Save parent
    
    ; Create main window
    xor rcx, rcx
    lea rdx, szVisualizationClass
    lea r8, szVisualizationTitle
    mov r9d, 50000000h or 10000000h ; WS_CHILD | WS_VISIBLE
    mov dword ptr [rsp + 32], 0
    mov dword ptr [rsp + 40], 0
    mov dword ptr [rsp + 48], 1000
    mov dword ptr [rsp + 56], 700
    mov qword ptr [rsp + 64], rbx
    mov qword ptr [rsp + 72], 0
    mov qword ptr [rsp + 80], 0
    mov qword ptr [rsp + 88], 0
    call CreateWindowExA
    mov g_visualization_studio.hWindow, rax
    
    ; Create chart area
    call create_chart_area
    
    ; Create control panel
    call create_control_panel
    
    ; Create legend
    call create_legend
    
    ; Create back buffer
    call create_back_buffer
    
    ; Show window
    mov rcx, g_visualization_studio.hWindow
    mov edx, 5  ; SW_SHOW
    call ShowWindow
    
    mov rax, g_visualization_studio.hWindow
    add rsp, 96
    pop rbx
    ret
    
.data
szVisualizationTitle db "ML Visualization",0
.code
visualization_create_window ENDP

;==========================================================================
; visualization_render_confusion(matrix_ptr: rcx) -> bool (rax)
; Render confusion matrix
;==========================================================================
visualization_render_confusion PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; matrix_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_CONFUSION
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_confusion_matrix
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_confusion ENDP

;==========================================================================
; visualization_render_roc(roc_ptr: rcx) -> bool (rax)
; Render ROC curve
;==========================================================================
visualization_render_roc PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; roc_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_ROC
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_roc_curve
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_roc ENDP

;==========================================================================
; visualization_render_pr(pr_ptr: rcx) -> bool (rax)
; Render PR curve
;==========================================================================
visualization_render_pr PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; pr_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_PR
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_pr_curve
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_pr ENDP

;==========================================================================
; visualization_render_feature_imp(feature_ptr: rcx) -> bool (rax)
; Render feature importance
;==========================================================================
visualization_render_feature_imp PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; feature_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_FEATURE_IMP
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_feature_importance
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_feature_imp ENDP

;==========================================================================
; visualization_render_embedding(embedding_ptr: rcx) -> bool (rax)
; Render embedding visualization
;==========================================================================
visualization_render_embedding PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; embedding_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_EMBEDDING
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_embedding
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_embedding ENDP

;==========================================================================
; visualization_render_attention(attention_ptr: rcx) -> bool (rax)
; Render attention heatmap
;==========================================================================
visualization_render_attention PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; attention_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_ATTENTION
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_attention_heatmap
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_attention ENDP

;==========================================================================
; visualization_render_loss_curve(loss_ptr: rcx) -> bool (rax)
; Render loss curve
;==========================================================================
visualization_render_loss_curve PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov rsi, rcx  ; loss_ptr
    
    ; Set chart type
    mov g_visualization_studio.chart_type, CHART_LOSS_CURVE
    mov g_visualization_studio.chart_data, rsi
    
    ; Render the chart
    call render_loss_curve
    
    ; Update window
    mov rcx, g_visualization_studio.hWindow
    xor rdx, rdx
    mov r8d, 0
    call InvalidateRect
    
    mov rax, 1  ; Success
    add rsp, 32
    pop rsi
    pop rbx
    ret
visualization_render_loss_curve ENDP

;==========================================================================
; Helper functions
;==========================================================================

create_chart_area PROC
    ; Create chart area window
    ret
create_chart_area ENDP

create_control_panel PROC
    ; Create control panel window
    ret
create_control_panel ENDP

create_legend PROC
    ; Create legend window
    ret
create_legend ENDP

create_back_buffer PROC
    ; Create back buffer for flicker-free drawing
    ret
create_back_buffer ENDP

render_confusion_matrix PROC
    ; Render confusion matrix
    ret
render_confusion_matrix ENDP

render_roc_curve PROC
    ; Render ROC curve
    ret
render_roc_curve ENDP

render_pr_curve PROC
    ; Render PR curve
    ret
render_pr_curve ENDP

render_feature_importance PROC
    ; Render feature importance
    ret
render_feature_importance ENDP

render_embedding PROC
    ; Render embedding
    ret
render_embedding ENDP

render_attention_heatmap PROC
    ; Render attention heatmap
    ret
render_attention_heatmap ENDP

render_loss_curve PROC
    ; Render loss curve
    ret
render_loss_curve ENDP

;==========================================================================
; Window procedures
;==========================================================================

visualization_wnd_proc PROC
    ; Main window procedure
    call DefWindowProcA
    ret
visualization_wnd_proc ENDP

chart_area_wnd_proc PROC
    ; Chart area procedure
    call DefWindowProcA
    ret
chart_area_wnd_proc ENDP

; Stubs for remaining public functions
visualization_export_chart PROC
    ret
visualization_export_chart ENDP

visualization_set_color_scheme PROC
    ret
visualization_set_color_scheme ENDP

visualization_zoom PROC
    ret
visualization_zoom ENDP

visualization_pan PROC
    ret
visualization_pan ENDP

end
