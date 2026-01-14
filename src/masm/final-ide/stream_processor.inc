; Stream Processor Header File
; Phase D Component 2: Event streaming pipeline

; Stream error codes
STREAM_SUCCESS equ 0
STREAM_ERROR_INVALID equ 1
STREAM_ERROR_OOM equ 2
STREAM_ERROR_NOT_FOUND equ 3
STREAM_ERROR_EXISTS equ 4
STREAM_ERROR_FULL equ 5
STREAM_ERROR_EMPTY equ 6
STREAM_ERROR_OFFSET equ 7

; Stream processor structure
STREAM_PROCESSOR STRUCT
    processor_mutex DWORD ?
    stream_count DWORD ?
    max_streams DWORD ?
    consumer_count DWORD ?
    max_consumers DWORD ?
    total_messages DWORD ?
    total_bytes DWORD ?
    streams_ptr DWORD ?
    consumers_ptr DWORD ?
    allocator_ptr DWORD ?
    deallocator_ptr DWORD ?
    stats_enabled DWORD ?
    reserved BYTE 16*4 dup(?)
STREAM_PROCESSOR ENDS

; Stream structure
STREAM STRUCT
    stream_id DWORD ?
    name_ptr DWORD ?
    name_len DWORD ?
    message_count DWORD ?
    first_message_ptr DWORD ?
    last_message_ptr DWORD ?
    consumer_count DWORD ?
    max_messages DWORD ?
    retention_ms DWORD ?
    created_at DWORD ?
    flags DWORD ?
    reserved BYTE 6*4 dup(?)
STREAM ENDS

; Message structure
MESSAGE STRUCT
    message_id DWORD ?
    stream_id DWORD ?
    timestamp DWORD ?
    data_ptr DWORD ?
    data_len DWORD ?
    next_ptr DWORD ?
    prev_ptr DWORD ?
    ack_count DWORD ?
    nack_count DWORD ?
    flags DWORD ?
    reserved BYTE 4*4 dup(?)
MESSAGE ENDS

; Consumer structure
CONSUMER STRUCT
    consumer_id DWORD ?
    stream_id DWORD ?
    name_ptr DWORD ?
    name_len DWORD ?
    current_offset DWORD ?
    last_message_id DWORD ?
    ack_count DWORD ?
    nack_count DWORD ?
    created_at DWORD ?
    flags DWORD ?
    reserved BYTE 6*4 dup(?)
CONSUMER ENDS

; Constants
STREAM_MAX_NAME_LEN equ 256
STREAM_MAX_MESSAGES equ 1000000
CONSUMER_MAX_NAME_LEN equ 256
MESSAGE_MAX_SIZE equ 1048576

; Function declarations
EXTERN stream_processor_init:proc
EXTERN stream_processor_shutdown:proc
EXTERN stream_create:proc
EXTERN stream_subscribe:proc
EXTERN stream_publish:proc
EXTERN stream_consume:proc
EXTERN stream_ack:proc
EXTERN stream_nack:proc
EXTERN stream_get_offset:proc
EXTERN stream_seek:proc
EXTERN stream_stats:proc
EXTERN stream_list:proc




