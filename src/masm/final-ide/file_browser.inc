;==============================================================================
; file_browser.inc - MASM File Browser Header
; Author: RawrXD CI/CD
; Date: Dec 29, 2025
;==============================================================================

IFNDEF FILE_BROWSER_INC
FILE_BROWSER_INC EQU 1

; File types
FILE_TYPE_UNKNOWN       EQU 0
FILE_TYPE_FILE          EQU 1
FILE_TYPE_DIRECTORY     EQU 2
FILE_TYPE_SYMLINK       EQU 3

; Project types
PROJECT_TYPE_NONE       EQU 0
PROJECT_TYPE_GIT        EQU 1
PROJECT_TYPE_CMAKE      EQU 2
PROJECT_TYPE_PYTHON     EQU 3
PROJECT_TYPE_RUST       EQU 4

; Function prototypes
IFNDEF @masm_file_browser_init
EXTERN masm_file_browser_init:PROC
ENDIF
IFNDEF @masm_file_browser_shutdown
EXTERN masm_file_browser_shutdown:PROC
ENDIF
IFNDEF @masm_file_browser_set_root
EXTERN masm_file_browser_set_root:PROC
ENDIF
IFNDEF @masm_file_browser_scan_directory
EXTERN masm_file_browser_scan_directory:PROC
ENDIF
IFNDEF @masm_file_browser_get_node
EXTERN masm_file_browser_get_node:PROC
ENDIF
IFNDEF @masm_file_browser_expand_node
EXTERN masm_file_browser_expand_node:PROC
ENDIF
IFNDEF @masm_file_browser_collapse_node
EXTERN masm_file_browser_collapse_node:PROC
ENDIF
IFNDEF @masm_file_browser_list_children
EXTERN masm_file_browser_list_children:PROC
ENDIF
IFNDEF @masm_file_browser_add_filter
EXTERN masm_file_browser_add_filter:PROC
ENDIF
IFNDEF @masm_file_browser_remove_filter
EXTERN masm_file_browser_remove_filter:PROC
ENDIF
IFNDEF @masm_file_browser_detect_project
EXTERN masm_file_browser_detect_project:PROC
ENDIF
IFNDEF @masm_file_browser_get_project_type
EXTERN masm_file_browser_get_project_type:PROC
ENDIF
IFNDEF @masm_file_browser_search_files
EXTERN masm_file_browser_search_files:PROC
ENDIF
IFNDEF @masm_file_browser_watch_changes
EXTERN masm_file_browser_watch_changes:PROC
ENDIF
IFNDEF @masm_file_browser_refresh_tree
EXTERN masm_file_browser_refresh_tree:PROC
ENDIF

ENDIF


