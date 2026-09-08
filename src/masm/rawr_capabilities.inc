; rawr_capabilities.inc — host/gpu facts + kernel shape (no vendor/tier tables)
IFNDEF RAWR_CAPABILITIES_INC
RAWR_CAPABILITIES_INC EQU 1

RawrHostCaps STRUCT
    AvailPhysical       QWORD ?
    AvailCommit         QWORD ?
    ProcessCommit       QWORD ?
    LogicalProcessors   DWORD ?
    _pad0               DWORD ?
RawrHostCaps ENDS

RawrGpuCaps STRUCT
    PhysicalDevice      QWORD ?
    Device              QWORD ?
    HeapSize            QWORD ?
    HeapBudget          QWORD ?
    HeapUsage           QWORD ?
    BudgetKnown         DWORD ?
    MaxSharedBytes      DWORD ?
    MaxWGInvocations    DWORD ?
    MaxWGX              DWORD ?
    MaxWGY              DWORD ?
    MaxWGZ              DWORD ?
    DefaultSubgroup     DWORD ?
    MinSubgroup         DWORD ?
    MaxSubgroup         DWORD ?
    TimestampValid      DWORD ?
RawrGpuCaps ENDS

RawrKernelShape STRUCT
    LocalX              DWORD ?
    LocalY              DWORD ?
    LocalZ              DWORD ?
    RowsPerWG           DWORD ?
    SharedBytes         DWORD ?
    PrefetchDepth       DWORD ?
    WindowCount         DWORD ?
    EstimatedLiveBytes  QWORD ?
    MeasuredTicks       QWORD ?
RawrKernelShape ENDS

ENDIF
