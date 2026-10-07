; =============================================================================
; P1_OutcomeReverseRuntime_x64.inc
; ABI for the dependency-free x64 outcome-reverse runtime ledger.
;
; Win64 ABI. Caller owns every buffer. The implementation imports nothing,
; allocates nothing, and uses integer/fixed-point accounting only.
; =============================================================================

IFNDEF P1_OUTCOME_REVERSE_RUNTIME_X64_INC
P1_OUTCOME_REVERSE_RUNTIME_X64_INC EQU 1

P1OR_ABI_VERSION                 EQU 00010000h
P1OR_TARGET_TPS                  EQU 100
P1OR_PHASE_COUNT                 EQU 6
P1OR_BASIS_POINTS               EQU 10000
P1OR_MAX_VRAM_BYTES             EQU 00000007C0000000h ; 31 GiB working ceiling
P1OR_MAX_ACTIVE_BYTES           EQU 00000000E0000000h ; 3.5 GiB/token ceiling
P1OR_REVERSE_SCALE              EQU 1000
P1OR_REVERSE_MULTIPLIER         EQU 2300             ; 2.3x
P1OR_REVERSE_EPSILON            EQU 1                ; 0.001
P1OR_REVERSE_MAX_PASSES         EQU 23

; Status codes returned in EAX.
P1OR_OK                          EQU 0
P1OR_EINVAL                      EQU 1
P1OR_ESTATE                      EQU 2
P1OR_ERANGE                      EQU 3
P1OR_EEMPTY                      EQU 4

; Reverse-budget phases.
P1OR_PHASE_WEIGHT_PATH           EQU 0
P1OR_PHASE_ATTENTION_KV          EQU 1
P1OR_PHASE_MOE_ROUTER            EQU 2
P1OR_PHASE_RING_PUBLICATION      EQU 3
P1OR_PHASE_SAMPLE_STREAM         EQU 4
P1OR_PHASE_RESERVE               EQU 5

; Context lifecycle.
P1OR_STATE_READY                 EQU 00000001h
P1OR_STATE_EPOCH_ACTIVE          EQU 00000002h
P1OR_STATE_SEALED                EQU 00000004h

; Per-phase sample flags.
P1OR_SAMPLE_VALID                EQU 00000001h
P1OR_SAMPLE_COMMITTED            EQU 00000002h
P1OR_SAMPLE_AUTHORITATIVE        EQU 00000004h
P1OR_SAMPLE_COHERENT             EQU 00000008h
P1OR_SAMPLE_RESIDENT             EQU 00000010h

; Publication/prefetch evidence flags.
P1OR_PUB_SLOT_PUBLISHED          EQU 00000001h
P1OR_PUB_GENERATION_MATCH        EQU 00000002h
P1OR_PUB_ACQUIRE_ORDERED         EQU 00000004h
P1OR_PUB_PAYLOAD_NONZERO         EQU 00000008h
P1OR_PUB_PREFETCH_OBSERVED       EQU 00000010h
P1OR_PUB_PREFETCH_CONTAINED      EQU 00000020h
P1OR_PUB_PROFILER_LIFETIME       EQU 00000040h
P1OR_PUB_AFFINITY_ATTEMPTED      EQU 00000080h ; informational, best effort
P1OR_PUB_SEQUENCE_MATCH          EQU 00000100h
P1OR_PUB_PAYLOAD_BOUNDS          EQU 00000200h

P1OR_PUB_AUTHORITY_MASK          EQU 0000030Fh
P1OR_PUB_PREFETCH_MASK           EQU 00000030h

; Sealed decision flags.
P1OR_DECISION_TPS_PASS           EQU 00000001h
P1OR_DECISION_VRAM_PASS          EQU 00000002h
P1OR_DECISION_PATH_PASS          EQU 00000004h
P1OR_DECISION_COHERENCE_PASS     EQU 00000008h
P1OR_DECISION_RESIDENCY_PASS     EQU 00000010h
P1OR_DECISION_PUBLICATION_PASS   EQU 00000020h
P1OR_DECISION_PREFETCH_PASS      EQU 00000040h
P1OR_DECISION_LIFETIME_PASS      EQU 00000080h
P1OR_DECISION_ACTIVE_BYTES_PASS  EQU 00000100h
P1OR_DECISION_CERT_PASS          EQU 00000200h

P1OR_DECISION_REQUIRED_MASK      EQU 000001FFh

; Retained-rule flags.
P1OR_RULE_RETAINED               EQU 00000001h
P1OR_RULE_CONTRACT_PASS          EQU 00000002h
P1OR_RULE_OUTPUT_STABLE          EQU 00000004h
P1OR_RULE_GAIN_PASS              EQU 00000008h

; Reverse-projection flags. Projection remains advisory; certification gates
; retain final authority.
P1OR_REVERSE_VALID               EQU 00000001h
P1OR_REVERSE_WITHIN_EPSILON      EQU 00000002h
P1OR_REVERSE_OVERSHOOT           EQU 00000004h

; Eight-byte ASCII signatures.
P1OR_CONTEXT_MAGIC               EQU 31585443524F3150h ; "P1ORCTX1"
P1OR_DECISION_MAGIC              EQU 31434544524F3150h ; "P1ORDEC1"
P1OR_RULE_MAGIC                  EQU 314C5552524F3150h ; "P1ORRUL1"
P1OR_DESCRIPTOR_MAGIC            EQU 31494241524F3150h ; "P1ORABI1"
P1OR_REVERSE_MAGIC               EQU 31564552524F3150h ; "P1ORREV1"

; One phase observation. BeginSample/CommitSample fill timestamps; callers fill
; byte, residency, path, and output fields before commit.
P1OR_PHASE_SAMPLE STRUCT 8
    PhaseId                     DD ?
    Flags                       DD ?
    StartTsc                    DQ ?
    EndTsc                      DQ ?
    ElapsedTicks                DQ ?
    BytesRead                   DQ ?
    BytesWritten                DQ ?
    ActiveBytes                 DQ ?
    VramBytes                   DQ ?
    PcieFaults                  DQ ?
    OutputHash                  DQ ?
    TokenSequence               DQ ?
P1OR_PHASE_SAMPLE ENDS

; Authority evidence for PASS2 publication followed by best-effort SMT
; prefetch. Affinity success is deliberately not a contract predicate.
P1OR_PUBLICATION_EVIDENCE STRUCT 8
    Flags                       DQ ?
    StatusBefore                DD ?
    StatusPublished             DD ?
    SlotIndex                   DQ ?
    PayloadPointer              DQ ?
    PayloadLength               DQ ?
    ProducerSequence            DQ ?
    ConsumerSequence            DQ ?
    PublishedGeneration         DQ ?
    AcquiredGeneration          DQ ?
    PublishTsc                  DQ ?
    AcquireTsc                  DQ ?
    PrefetchStartTsc            DQ ?
    PrefetchEndTsc              DQ ?
    PrefetchLeadCycles          DQ ?
    OverlapCycles               DQ ?
    PayloadNonzeroBytes         DQ ?
    Reserved                    DQ ?
P1OR_PUBLICATION_EVIDENCE ENDS

; One caller-owned context per measured stream/epoch.
P1OR_CONTEXT STRUCT 8
    Magic                       DQ ?
    Version                     DD ?
    PhaseCount                  DD ?
    StateFlags                  DQ ?
    TscHz                       DQ ?
    TargetTps                   DQ ?
    TargetTicks                 DQ ?
    MaxVramBytes                DQ ?
    MaxActiveBytes              DQ ?
    Epoch                       DQ ?
    CommittedTokens             DQ ?
    PeakVramBytes               DQ ?
    PeakActiveBytes             DQ ?
    PcieFaults                  DQ ?
    LastOutputHash              DQ ?
    LastCommitFlags             DQ ?
    CommitFlagsAggregate        DQ ?
    PublicationFlags            DQ ?
    PrefetchLeadCycles          DQ ?
    OverlapCycles               DQ ?
    PhaseBudgetTicks            DQ P1OR_PHASE_COUNT DUP(?)
    PhaseElapsedTicks           DQ P1OR_PHASE_COUNT DUP(?)
    PhaseDebtTicks              DQ P1OR_PHASE_COUNT DUP(?)
    PhaseBytesRead              DQ P1OR_PHASE_COUNT DUP(?)
    PhaseBytesWritten           DQ P1OR_PHASE_COUNT DUP(?)
    PhaseActiveMax              DQ P1OR_PHASE_COUNT DUP(?)
    PhaseSampleCount            DQ P1OR_PHASE_COUNT DUP(?)
    PhaseMaxTicks               DQ P1OR_PHASE_COUNT DUP(?)
    TotalSamples                DQ ?
    Reserved                    DQ 3 DUP(?)
P1OR_CONTEXT ENDS

P1OR_DECISION STRUCT 8
    Magic                       DQ ?
    Version                     DD ?
    LargestDebtPhase            DD ?
    Flags                       DQ ?
    ObservedTps                 DQ ?
    AverageTicks                DQ ?
    TargetTicks                 DQ ?
    TotalTicks                  DQ ?
    TotalDebtTicks              DQ ?
    PeakVramBytes               DQ ?
    PeakActiveBytes             DQ ?
    PcieFaults                  DQ ?
    CommittedTokens             DQ ?
    OutputHash                  DQ ?
    PrefetchLeadCycles          DQ ?
    OverlapCycles               DQ ?
    PublicationFlags            DQ ?
    PhaseDebtTicks              DQ P1OR_PHASE_COUNT DUP(?)
    Reserved                    DQ 2 DUP(?)
P1OR_DECISION ENDS

P1OR_RULE_DECISION STRUCT 8
    Magic                       DQ ?
    Version                     DD ?
    ChangedPhase                DD ?
    Flags                       DQ ?
    GainTicks                   DQ ?
    GainBasisPoints             DQ ?
    BaselineTicks               DQ ?
    CandidateTicks              DQ ?
    BaselineHash                DQ ?
    CandidateHash               DQ ?
    Reserved                    DQ 2 DUP(?)
P1OR_RULE_DECISION ENDS

P1OR_REVERSE_PROJECTION STRUCT 8
    Magic                       DQ ?
    Version                     DD ?
    PassLimit                   DD ?
    Flags                       DQ ?
    DebtTicks                   DQ ?
    MeasuredGainTicks           DQ ?
    ProjectedGainTicks          DQ ?
    ResidualTicks               DQ ?
    ReferenceTicks              DQ ?
    EpsilonTicks                DQ ?
    MultiplierMilli             DQ ?
    Reserved                    DQ ?
P1OR_REVERSE_PROJECTION ENDS

P1OR_ABI_DESCRIPTOR STRUCT 8
    Magic                       DQ ?
    Version                     DD ?
    PhaseCount                  DD ?
    ContextSize                 DQ ?
    SampleSize                  DQ ?
    PublicationEvidenceSize     DQ ?
    DecisionSize                DQ ?
    RuleDecisionSize            DQ ?
    ReverseProjectionSize       DQ ?
P1OR_ABI_DESCRIPTOR ENDS

P1OR_CONTEXT_SIZE               EQU SIZEOF P1OR_CONTEXT
P1OR_PHASE_SAMPLE_SIZE          EQU SIZEOF P1OR_PHASE_SAMPLE
P1OR_PUBLICATION_EVIDENCE_SIZE  EQU SIZEOF P1OR_PUBLICATION_EVIDENCE
P1OR_DECISION_SIZE              EQU SIZEOF P1OR_DECISION
P1OR_RULE_DECISION_SIZE         EQU SIZEOF P1OR_RULE_DECISION
P1OR_REVERSE_PROJECTION_SIZE    EQU SIZEOF P1OR_REVERSE_PROJECTION

ENDIF
