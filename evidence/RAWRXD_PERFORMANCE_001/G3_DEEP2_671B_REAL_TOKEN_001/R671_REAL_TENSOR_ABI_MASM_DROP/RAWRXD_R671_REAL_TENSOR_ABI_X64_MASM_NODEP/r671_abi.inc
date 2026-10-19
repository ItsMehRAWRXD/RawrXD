option casemap:none

R671_OK                equ 0
R671_E_INVALID         equ 1
R671_E_OPEN            equ 2
R671_E_SIZE            equ 3
R671_E_MAPPING         equ 4
R671_E_VIEW            equ 5
R671_E_RANGE           equ 6
R671_E_STATE           equ 7

R671_MAX_U64           equ 0FFFFFFFFFFFFFFFFh

; Win32 constants
GENERIC_READ           equ 80000000h
FILE_SHARE_READ        equ 00000001h
OPEN_EXISTING          equ 3
FILE_ATTRIBUTE_NORMAL  equ 00000080h
PAGE_READONLY          equ 02h
FILE_MAP_READ          equ 0004h
INVALID_HANDLE_VALUE   equ -1

R671Context STRUCT
    file_handle         QWORD ?
    mapping_handle      QWORD ?
    file_bytes          QWORD ?
    allocation_gran     QWORD ?
    acquire_count       QWORD ?
    failed_acquires     QWORD ?
    release_count       QWORD ?
    live_leases         QWORD ?
    mapped_bytes_live   QWORD ?
    mapped_bytes_peak   QWORD ?
    newly_mapped_bytes  QWORD ?
R671Context ENDS

R671Lease STRUCT
    view_base           QWORD ?
    view_bytes          QWORD ?
    data_ptr            QWORD ?
    bytes               QWORD ?
    request_offset      QWORD ?
    aligned_offset      QWORD ?
    delta               QWORD ?
    generation_id       QWORD ?
    active              QWORD ?
R671Lease ENDS

R671TensorDesc STRUCT
    file_offset         QWORD ?
    byte_length         QWORD ?
    element_count       QWORD ?
    element_bytes       QWORD ?
    tensor_type         DWORD ?
    reserved            DWORD ?
R671TensorDesc ENDS

R671PrimitiveResult STRUCT
    elements_consumed   QWORD ?
    nonfinite_count     QWORD ?
    checksum_u64        QWORD ?
    scalar_f32_bits     DWORD ?
    status              DWORD ?
R671PrimitiveResult ENDS

r671_open PROTO
r671_tensor_acquire PROTO
r671_release PROTO
r671_close PROTO

; Concrete primitive: consumes the bytes behind lease.ptr.
; For tensor_type=0 (F32), computes scalar sum of all finite float32 elements.
; For all other tensor types, computes a byte checksum only and returns
; R671_E_INVALID for scalar math so quantized data can never be misrepresented
; as valid F32 arithmetic.
Deep2R671TensorPrimitive PROTO
