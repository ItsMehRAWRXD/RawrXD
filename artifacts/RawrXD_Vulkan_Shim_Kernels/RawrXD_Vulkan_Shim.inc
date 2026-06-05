; ============================================================================
; RawrXD_Vulkan_Shim.inc — Shared structure offsets
; ============================================================================
; Keep this synchronized with C++ struct packing/layout.
; ============================================================================

GpuTensorHandle_id          EQU 0
GpuTensorHandle_buffer      EQU 8
GpuTensorHandle_memory      EQU 16
GpuTensorHandle_SIZE        EQU 24

MatMulDesc_A                EQU 0
MatMulDesc_B                EQU 18h
MatMulDesc_Out              EQU 30h
MatMulDesc_M                EQU 48h
MatMulDesc_N                EQU 4Ch
MatMulDesc_K                EQU 50h
MatMulDesc_batch_count      EQU 54h
MatMulDesc_alpha            EQU 58h
MatMulDesc_beta             EQU 5Ch
MatMulDesc_pipeline         EQU 68h
MatMulDesc_layout           EQU 70h
MatMulDesc_descriptor_set   EQU 78h
MatMulDesc_push_data        EQU 80h
MatMulDesc_SIZE             EQU 90h

KVAppendDesc_num_tokens     EQU 30h
KVAppendDesc_pipeline       EQU 40h
KVAppendDesc_layout         EQU 48h
KVAppendDesc_descriptor_set EQU 50h
KVAppendDesc_push_data      EQU 58h
KVAppendDesc_SIZE           EQU 70h

RMSNormArgs_cmd_buffer      EQU 0
RMSNormArgs_fence           EQU 8
RMSNormArgs_queue           EQU 10h
RMSNormArgs_submit_info     EQU 28h
RMSNormArgs_SIZE            EQU 50h

SubmitGraphInfo_count       EQU 0
SubmitGraphInfo_cmd_bufs    EQU 8
SubmitGraphInfo_signal_sem  EQU 10h
SubmitGraphInfo_signal_val  EQU 18h
SubmitGraphInfo_queue       EQU 20h
SubmitGraphInfo_submit      EQU 28h
SubmitGraphInfo_SIZE        EQU 80h

; Impl anchor offsets used by shim (update when PIMPL changes)
IMPL_device                 EQU 20h
IMPL_queue                  EQU 28h
IMPL_cmd_buffer             EQU 30h
IMPL_fence                  EQU 38h
IMPL_timeline_semaphore     EQU 0A0h
IMPL_timeline_value         EQU 0A8h
