; Distributed Executor Header File
; Phase D Component 3: Multi-machine execution

; Distributed executor error codes
DISTRIBUTED_SUCCESS equ 0
DISTRIBUTED_ERROR_INVALID equ 1
DISTRIBUTED_ERROR_OOM equ 2
DISTRIBUTED_ERROR_NOT_FOUND equ 3
DISTRIBUTED_ERROR_EXISTS equ 4
DISTRIBUTED_ERROR_FULL equ 5
DISTRIBUTED_ERROR_OFFLINE equ 6
DISTRIBUTED_ERROR_NETWORK equ 7

; Distributed executor structure
DISTRIBUTED_EXECUTOR STRUCT
    executor_mutex DWORD ?
    node_count DWORD ?
    max_nodes DWORD ?
    job_count DWORD ?
    max_jobs DWORD ?
    nodes_ptr DWORD ?
    jobs_ptr DWORD ?
    allocator_ptr DWORD ?
    deallocator_ptr DWORD ?
    stats_enabled DWORD ?
    reserved BYTE 16*4 dup(?)
DISTRIBUTED_EXECUTOR ENDS

; Node structure
NODE STRUCT
    node_id DWORD ?
    name_ptr DWORD ?
    name_len DWORD ?
    address_ptr DWORD ?
    address_len DWORD ?
    port DWORD ?
    status DWORD ?
    capacity DWORD ?
    current_jobs DWORD ?
    last_heartbeat DWORD ?
    flags DWORD ?
    reserved BYTE 4*4 dup(?)
NODE ENDS

; Job structure
JOB STRUCT
    job_id DWORD ?
    node_id DWORD ?
    command_ptr DWORD ?
    command_len DWORD ?
    input_ptr DWORD ?
    input_len DWORD ?
    output_ptr DWORD ?
    output_len DWORD ?
    status DWORD ?
    exit_code DWORD ?
    created_at DWORD ?
    started_at DWORD ?
    completed_at DWORD ?
    flags DWORD ?
    reserved BYTE 4*4 dup(?)
JOB ENDS

; Constants
NODE_MAX_NAME_LEN equ 256
NODE_MAX_ADDRESS_LEN equ 256
JOB_MAX_COMMAND_LEN equ 4096
JOB_MAX_INPUT_LEN equ 1048576
JOB_MAX_OUTPUT_LEN equ 1048576

; Function declarations
EXTERN distributed_executor_init:proc
EXTERN distributed_executor_shutdown:proc
EXTERN distributed_register_node:proc
EXTERN distributed_submit_job:proc
EXTERN distributed_get_status:proc
EXTERN distributed_cancel_job:proc




