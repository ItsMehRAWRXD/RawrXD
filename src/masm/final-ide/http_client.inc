;==============================================================================
; http_client.inc - HTTP Client Include File
; ==============================================================================
; Provides declarations for the HTTP client system.
;==============================================================================

; HTTP methods
HTTP_METHOD_GET     EQU 1
HTTP_METHOD_POST    EQU 2
HTTP_METHOD_PUT     EQU 3
HTTP_METHOD_DELETE  EQU 4

; HTTP status codes
HTTP_STATUS_OK      EQU 200
HTTP_STATUS_CREATED EQU 201
HTTP_STATUS_BAD_REQUEST EQU 400
HTTP_STATUS_NOT_FOUND EQU 404
HTTP_STATUS_ERROR   EQU 500

; Structures
HTTP_REQUEST STRUCT
    method          DWORD ?
    url             QWORD ?
    headers         QWORD ?
    body            QWORD ?
    body_len        QWORD ?
    timeout         DWORD ?
HTTP_REQUEST ENDS

HTTP_CLIENT STRUCT
    hSession        QWORD ?
    hConnect        QWORD ?
    base_url        QWORD ?
    timeout         DWORD ?
    user_agent      QWORD ?
HTTP_CLIENT ENDS

; External function declarations
EXTERN HttpClientInitialize:PROC
EXTERN HttpClientRequest:PROC
EXTERN HttpClientShutdown:PROC

; Global client instance
EXTERN g_HttpClient:HTTP_CLIENT





