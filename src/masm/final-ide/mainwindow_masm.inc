;==============================================================================
; mainwindow_masm.inc - MASM MainWindow Architecture Header
; Author: RawrXD CI/CD
; Date: Dec 29, 2025
;==============================================================================

IFNDEF MAINWINDOW_MASM_INC
MAINWINDOW_MASM_INC EQU 1

; Window state constants
WINDOW_STATE_CLOSED         EQU 0
WINDOW_STATE_CREATED        EQU 1
WINDOW_STATE_SHOWN          EQU 2
WINDOW_STATE_HIDDEN         EQU 3
WINDOW_STATE_MAXIMIZED      EQU 4
WINDOW_STATE_MINIMIZED      EQU 5
WINDOW_STATE_FULLSCREEN     EQU 6

; Dock positions
DOCK_POS_LEFT               EQU 0
DOCK_POS_RIGHT              EQU 1
DOCK_POS_TOP                EQU 2
DOCK_POS_BOTTOM             EQU 3
DOCK_POS_FLOATING           EQU 4

; Menu types
MENU_TYPE_FILE              EQU 0
MENU_TYPE_EDIT              EQU 1
MENU_TYPE_VIEW              EQU 2
MENU_TYPE_TOOLS             EQU 3
MENU_TYPE_HELP              EQU 4

; Function prototypes
EXTERN masm_mainwindow_init:PROC
EXTERN masm_mainwindow_shutdown:PROC
EXTERN masm_mainwindow_create:PROC
EXTERN masm_mainwindow_show:PROC
EXTERN masm_mainwindow_hide:PROC
EXTERN masm_mainwindow_close:PROC
EXTERN masm_mainwindow_resize:PROC
EXTERN masm_mainwindow_set_title:PROC
EXTERN masm_mainwindow_add_dock:PROC
EXTERN masm_mainwindow_remove_dock:PROC
EXTERN masm_mainwindow_show_dock:PROC
EXTERN masm_mainwindow_hide_dock:PROC
EXTERN masm_mainwindow_add_menu_item:PROC
EXTERN masm_mainwindow_remove_menu_item:PROC
EXTERN masm_mainwindow_set_status:PROC
EXTERN masm_mainwindow_get_status:PROC
EXTERN masm_mainwindow_set_theme:PROC
EXTERN masm_mainwindow_get_theme:PROC
EXTERN masm_mainwindow_dispatch_signal:PROC
EXTERN masm_mainwindow_list_docks:PROC
EXTERN masm_mainwindow_save_layout:PROC
EXTERN masm_mainwindow_load_layout:PROC

ENDIF
