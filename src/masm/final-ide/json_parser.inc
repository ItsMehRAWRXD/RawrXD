;==============================================================================
; json_parser.inc - JSON Parser Include File
; ==============================================================================
; Provides declarations for the JSON parsing system.
;==============================================================================

; JSON value types
JSON_TYPE_NULL      EQU 0
JSON_TYPE_STRING    EQU 1
JSON_TYPE_NUMBER    EQU 2
JSON_TYPE_BOOLEAN   EQU 3
JSON_TYPE_OBJECT    EQU 4
JSON_TYPE_ARRAY     EQU 5

; Structures
JSON_VALUE STRUCT
    value_type      DWORD ?
    string_value    QWORD ?
    number_value    REAL8 ?
    bool_value      DWORD ?
    object_value    QWORD ?
    array_value     QWORD ?
JSON_VALUE ENDS

; External function declarations
EXTERN JsonParse:PROC
EXTERN JsonGetString:PROC
EXTERN JsonFree:PROC





