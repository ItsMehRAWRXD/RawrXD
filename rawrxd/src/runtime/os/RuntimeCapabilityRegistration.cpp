// ============================================================================
// RuntimeCapabilityRegistration.cpp — Generated bootstrap registration
// Registers all generated capabilities into the RuntimeKernel.
// ============================================================================
#include "RuntimeKernel.hpp"
#include "RuntimeCapabilityIds.hpp"

#include "CompilerCapability.hpp"
#include "LinkerCapability.hpp"
#include "BuilderCapability.hpp"
#include "LoaderCapability.hpp"
#include "PackageCapability.hpp"
#include "GenerationCapability.hpp"
#include "DebuggerCapability.hpp"
#include "ProfilerCapability.hpp"
#include "AssemblerCapability.hpp"
#include "OptimizerCapability.hpp"
#include "EmitterCapability.hpp"
#include "SelfHostCapability.hpp"
#include "ParserCapability.hpp"
#include "LexerCapability.hpp"
#include "SemanticCapability.hpp"
#include "IRCapability.hpp"
#include "SSACapability.hpp"
#include "CodeGenCapability.hpp"
#include "ClockCapability.hpp"
#include "TimerCapability.hpp"
#include "EventLoopCapability.hpp"
#include "MessageQueueCapability.hpp"
#include "TaskSchedulerCapability.hpp"
#include "ResourceSchedulerCapability.hpp"
#include "DeviceCapability.hpp"
#include "FilesystemCapability.hpp"
#include "StorageCapability.hpp"
#include "NetworkCapability.hpp"
#include "ConsoleCapability.hpp"
#include "WindowingCapability.hpp"
#include "InputCapability.hpp"
#include "DisplayCapability.hpp"
#include "PowerCapability.hpp"
#include "CrashHandlerCapability.hpp"
#include "ExceptionCapability.hpp"
#include "DiagnosticsCapability.hpp"
#include "HealthCapability.hpp"
#include "TelemetryCapability.hpp"
#include "EvidenceCapability.hpp"
#include "ReceiptCapability.hpp"
#include "StateStoreCapability.hpp"
#include "SnapshotCapability.hpp"
#include "VersionCapability.hpp"
#include "ProcessCapability.hpp"
#include "ThreadCapability.hpp"
#include "FiberCapability.hpp"
#include "IPCCapability.hpp"
#include "SecurityCapability.hpp"
#include "ReflectionCapability.hpp"
#include "MetadataCapability.hpp"
#include "BootstrapCapability.hpp"
#include "SelfCertificationCapability.hpp"
#include "RecoveryCapability.hpp"
#include "AuthorityCapability.hpp"
#include "KernelServicesCapability.hpp"
#include "ServiceRegistryCapability.hpp"
#include "ObjectRegistryCapability.hpp"
#include "HandleTableCapability.hpp"
#include "ObjectFactoryCapability.hpp"
#include "EntityRegistryCapability.hpp"
#include "RelationshipRegistryCapability.hpp"
#include "ConstraintRegistryCapability.hpp"
#include "TransitionRegistryCapability.hpp"
#include "CapabilityGraphCapability.hpp"
#include "ExecutionGraphCapability.hpp"
#include "ResourceGraphCapability.hpp"
#include "StateGraphCapability.hpp"
#include "AuthorityGraphCapability.hpp"
#include "EvidenceRegistryCapability.hpp"
#include "ReceiptRegistryCapability.hpp"
#include "SnapshotRegistryCapability.hpp"
#include "HistoryRegistryCapability.hpp"
#include "AdmissionRegistryCapability.hpp"
#include "DiscoveryRegistryCapability.hpp"
#include "ExecutionRegistryCapability.hpp"
#include "VerificationRegistryCapability.hpp"
#include "CapabilityDatabaseCapability.hpp"
#include "KnowledgeRegistryCapability.hpp"
#include "GenerationRegistryCapability.hpp"
#include "GenerationPipelineCapability.hpp"
#include "LifecycleRegistryCapability.hpp"
#include "CapabilityNegotiatorCapability.hpp"
#include "CapabilityAuthorityCapability.hpp"
#include "CapabilityAdmissionCapability.hpp"
#include "CapabilityLifecycleCapability.hpp"
#include "CapabilityEvidenceCapability.hpp"
#include "CapabilityMetricsCapability.hpp"
#include "CapabilityHealthCapability.hpp"
#include "CapabilityPolicyCapability.hpp"
#include "CapabilitySnapshotCapability.hpp"
#include "CapabilityReplayCapability.hpp"
#include "CapabilityCheckpointCapability.hpp"
#include "CapabilityRollbackCapability.hpp"
#include "CapabilityMigrationCapability.hpp"
#include "CapabilityReplicationCapability.hpp"
#include "CapabilitySynchronizationCapability.hpp"
#include "CapabilityCompositionCapability.hpp"
#include "CapabilityDiscoveryCapability.hpp"
#include "CapabilityResolverCapability.hpp"
#include "CapabilitySchedulerCapability.hpp"
#include "CapabilityDispatcherCapability.hpp"
#include "CapabilityExecutorCapability.hpp"
#include "CapabilityResourceMapCapability.hpp"
#include "CapabilityDependencyGraphCapability.hpp"
#include "CapabilityStateCapability.hpp"
#include "CapabilityContextCapability.hpp"
#include "CapabilityDescriptorCapability.hpp"
#include "CapabilityManifestCapability.hpp"
#include "CapabilityContractCapability.hpp"
#include "CapabilityNegotiationGraphCapability.hpp"
#include "CapabilityExecutionGraphCapability.hpp"
#include "InstructionSetCapability.hpp"
#include "OpcodeRegistryCapability.hpp"
#include "ExecutionEngineCapability.hpp"
#include "IRDatabaseCapability.hpp"
#include "SymbolDatabaseCapability.hpp"
#include "TypeDatabaseCapability.hpp"
#include "ModuleDatabaseCapability.hpp"
#include "PackageDatabaseCapability.hpp"
#include "ProjectDatabaseCapability.hpp"
#include "WorkspaceDatabaseCapability.hpp"
#include "SessionDatabaseCapability.hpp"
#include "CacheManagerCapability.hpp"
#include "ObjectCacheCapability.hpp"
#include "StringPoolCapability.hpp"
#include "HashDatabaseCapability.hpp"
#include "UUIDRegistryCapability.hpp"
#include "IdentityManagerCapability.hpp"
#include "TransactionEngineCapability.hpp"
#include "CommitLogCapability.hpp"
#include "DeltaEngineCapability.hpp"
#include "MergeEngineCapability.hpp"
#include "ConflictResolverCapability.hpp"
#include "DeterminismEngineCapability.hpp"
#include "CertificationEngineCapability.hpp"
#include "RealityEngineCapability.hpp"
#include "BeaconSchedulerCapability.hpp"
#include "BeaconDispatcherCapability.hpp"
#include "BeaconResolverCapability.hpp"
#include "BeaconPlannerCapability.hpp"
#include "BeaconExecutorCapability.hpp"
#include "BeaconConsensusCapability.hpp"
#include "BeaconReplicationCapability.hpp"
#include "BeaconSynchronizationCapability.hpp"
#include "KernelCoreCapability.hpp"
#include "KernelUniverseCapability.hpp"
#include "KernelTopologyCapability.hpp"
#include "KernelSchedulerCapability.hpp"
#include "KernelDispatcherCapability.hpp"
#include "KernelExecutorCapability.hpp"
#include "KernelCoordinatorCapability.hpp"
#include "KernelCompositionCapability.hpp"
#include "KernelResolverCapability.hpp"
#include "KernelAdmissionCapability.hpp"
#include "KernelNegotiationCapability.hpp"
#include "KernelObservationCapability.hpp"
#include "KernelVerificationCapability.hpp"
#include "KernelPersistenceCapability.hpp"
#include "KernelLifecycleCapability.hpp"
#include "KernelIdentityCapability.hpp"
#include "KernelGraphCapability.hpp"
#include "KernelRegistryCapability.hpp"
#include "KernelAuthorityCapability.hpp"
#include "KernelContractsCapability.hpp"
#include "KernelInvariantsCapability.hpp"
#include "KernelEvidenceCapability.hpp"
#include "KernelPoliciesCapability.hpp"
#include "KernelDecisionsCapability.hpp"
#include "KernelGoalsCapability.hpp"
#include "KernelPlannerCapability.hpp"
#include "KernelReasonerCapability.hpp"
#include "KernelKnowledgeCapability.hpp"
#include "KernelMemoryCapability.hpp"
#include "KernelRealityCapability.hpp"
#include "KernelCapabilitiesCapability.hpp"
#include "KernelResourcesCapability.hpp"
#include "KernelExecutionCapability.hpp"
#include "KernelCertificationCapability.hpp"
#include "KernelGenerationCapability.hpp"
#include "KernelBootstrapCapability.hpp"
#include "KernelManifestCapability.hpp"
#include "KernelDescriptorCapability.hpp"
#include "KernelMetadataCapability.hpp"
#include "KernelNamespaceCapability.hpp"
#include "KernelTypeSystemCapability.hpp"
#include "KernelABICapability.hpp"
#include "KernelLoaderCapability.hpp"
#include "KernelEmitterCapability.hpp"
#include "KernelSerializerCapability.hpp"
#include "KernelDeserializerCapability.hpp"
#include "KernelMigrationCapability.hpp"
#include "KernelCompatibilityCapability.hpp"
#include "KernelDiagnosticsCapability.hpp"
#include "KernelProfilerCapability.hpp"
#include "KernelOptimizerCapability.hpp"
#include "KernelHotPatchCapability.hpp"
#include "KernelRecoveryCapability.hpp"
#include "KernelReplayCapability.hpp"
#include "KernelSnapshotCapability.hpp"
#include "KernelSealCapability.hpp"
#include "KernelRootCapability.hpp"
#include "KernelHostCapability.hpp"
#include "KernelPlatformCapability.hpp"
#include "KernelEnvironmentCapability.hpp"
#include "KernelConfigurationCapability.hpp"
#include "KernelBootCapability.hpp"
#include "KernelSessionCapability.hpp"
#include "KernelWorkspaceCapability.hpp"
#include "KernelProjectCapability.hpp"
#include "KernelArtifactCapability.hpp"
#include "KernelModuleCapability.hpp"
#include "KernelPackageCapability.hpp"
#include "KernelImageCapability.hpp"
#include "KernelProcessCapability.hpp"
#include "KernelThreadCapability.hpp"
#include "KernelFiberCapability.hpp"
#include "KernelDeviceCapability.hpp"
#include "KernelServiceCapability.hpp"
#include "KernelRootAuthorityCapability.hpp"
#include "GoalEngineCapability.hpp"
#include "DecisionEngineCapability.hpp"
#include "EvidenceGraphCapability.hpp"
#include "ReasoningGraphCapability.hpp"
#include "PlanningGraphCapability.hpp"
#include "ContextGraphCapability.hpp"
#include "WorldStateGraphCapability.hpp"
#include "ConfidenceEngineCapability.hpp"
#include "ConsistencyEngineCapability.hpp"
#include "QualityEngineCapability.hpp"
#include "ConstraintGraphCapability.hpp"
#include "CapabilityArbitratorCapability.hpp"
#include "GenerationOrchestratorCapability.hpp"
#include "RealityGraphCapability.hpp"
#include "UniversalCapabilityRegistryCapability.hpp"
#include "ModelAdmissionEngineCapability.hpp"
#include "ModelCapabilityEngineCapability.hpp"
#include "ModelTranslationEngineCapability.hpp"
#include "InferenceKernelCapability.hpp"
#include "InferenceSchedulerCapability.hpp"
#include "InferencePlannerCapability.hpp"
#include "TensorRegistryCapability.hpp"
#include "TensorSchedulerCapability.hpp"
#include "TensorMemoryCapability.hpp"
#include "OperationRegistryCapability.hpp"
#include "OperationSchedulerCapability.hpp"
#include "OperationFusionCapability.hpp"
#include "GraphOptimizerCapability.hpp"
#include "KernelFusionCapability.hpp"
#include "AttentionEngineCapability.hpp"
#include "MoEEngineCapability.hpp"
#include "KVEngineCapability.hpp"
#include "TokenizerEngineCapability.hpp"
#include "SamplingEngineCapability.hpp"
#include "DecodeEngineCapability.hpp"
#include "StreamEngineCapability.hpp"
#include "KnowledgeEngineCapability.hpp"
#include "MemoryEngineCapability.hpp"
#include "LearningEngineCapability.hpp"
#include "SelfImprovementEngineCapability.hpp"
#include "ReflectionEngineCapability.hpp"
#include "HypothesisEngineCapability.hpp"
#include "SimulationEngineCapability.hpp"
#include "PredictionEngineCapability.hpp"
#include "OptimizationEngineCapability.hpp"
#include "CompositionEngineCapability.hpp"
#include "AdaptationEngineCapability.hpp"
#include "CoordinationEngineCapability.hpp"
#include "GenerationKernelCapability.hpp"
#include "GenerationAuthorityCapability.hpp"
#include "GenerationSubjectCapability.hpp"
#include "GenerationLedgerCapability.hpp"
#include "GenerationReplayCapability.hpp"
#include "GenerationArchiveCapability.hpp"
#include "GenerationHistoryCapability.hpp"
#include "GenerationEvidenceCapability.hpp"
#include "GenerationIdentityCapability.hpp"
#include "GenerationStateCapability.hpp"
#include "GenerationManifestCapability.hpp"
#include "GenerationContractCapability.hpp"
#include "GenerationAuthorityBoundaryCapability.hpp"
#include "ProducerBoundaryCapability.hpp"
#include "ExternalOracleRegistryCapability.hpp"
#include "OracleSubjectCapability.hpp"
#include "OracleEvidenceCapability.hpp"
#include "OracleComparisonCapability.hpp"
#include "OracleTruthEngineCapability.hpp"
#include "OracleIsolationCapability.hpp"
#include "OracleDeterminismCapability.hpp"
#include "OracleLogitsParityCapability.hpp"
#include "OracleHiddenParityCapability.hpp"
#include "OracleCheckpointRegistryCapability.hpp"
#include "OracleReceiptCapability.hpp"
#include "CertificationAuthorityCapability.hpp"
#include "SubjectFreezeEngineCapability.hpp"
#include "SubjectFingerprintCapability.hpp"
#include "EvidenceChainCapability.hpp"
#include "IndependentProbeCapability.hpp"
#include "OracleExecutionCapability.hpp"
#include "OracleStateCaptureCapability.hpp"
#include "NumericalTruthEngineCapability.hpp"
#include "StructuralTruthEngineCapability.hpp"
#include "ConstraintTruthEngineCapability.hpp"
#include "TruthConsensusEngineCapability.hpp"
#include "CertificationLedgerCapability.hpp"
#include "ImmutableReceiptCapability.hpp"
#include "AuthorityPipelineCapability.hpp"
#include "TruthRegistryCapability.hpp"
#include "OracleRegistryCapability.hpp"
#include "SubjectRegistryCapability.hpp"
#include "AuthorityRegistryCapability.hpp"
#include "VerdictRegistryCapability.hpp"
#include "CertificationKernelCapability.hpp"

namespace rawrxd::runtime {

void registerAllGeneratedCapabilities(RuntimeRegistry& registry) {
    registry.registerCapability(std::make_unique<rawrxd::runtime::CompilerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::LinkerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BuilderCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::LoaderCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::PackageCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::GenerationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DebuggerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ProfilerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::AssemblerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::OptimizerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::EmitterCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SelfHostCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ParserCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::LexerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SemanticCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::IRCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SSACapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CodeGenCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ClockCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TimerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::EventLoopCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::MessageQueueCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TaskSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ResourceSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DeviceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::FilesystemCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::StorageCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::NetworkCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ConsoleCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::WindowingCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::InputCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DisplayCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::PowerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CrashHandlerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ExceptionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DiagnosticsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::HealthCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TelemetryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::EvidenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ReceiptCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::StateStoreCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SnapshotCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::VersionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ProcessCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ThreadCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::FiberCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::IPCCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SecurityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ReflectionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::MetadataCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BootstrapCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SelfCertificationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::RecoveryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::AuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::KernelServicesCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ServiceRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ObjectRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::HandleTableCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ObjectFactoryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::EntityRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::RelationshipRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ConstraintRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TransitionRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ExecutionGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ResourceGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::StateGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::AuthorityGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::EvidenceRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ReceiptRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SnapshotRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::HistoryRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::AdmissionRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DiscoveryRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ExecutionRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::VerificationRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::KnowledgeRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::GenerationRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::GenerationPipelineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::LifecycleRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityNegotiatorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityAuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityAdmissionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityLifecycleCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityEvidenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityMetricsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityHealthCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityPolicyCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilitySnapshotCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityReplayCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityCheckpointCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityRollbackCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityMigrationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityReplicationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilitySynchronizationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityCompositionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityDiscoveryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityResolverCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilitySchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityDispatcherCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityExecutorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityResourceMapCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityDependencyGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityStateCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityContextCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityDescriptorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityManifestCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityContractCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityNegotiationGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CapabilityExecutionGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::InstructionSetCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::OpcodeRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ExecutionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::IRDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SymbolDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TypeDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ModuleDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::PackageDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ProjectDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::WorkspaceDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::SessionDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CacheManagerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ObjectCacheCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::StringPoolCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::HashDatabaseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::UUIDRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::IdentityManagerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::TransactionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CommitLogCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DeltaEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::MergeEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::ConflictResolverCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::DeterminismEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::CertificationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::RealityEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconDispatcherCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconResolverCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconPlannerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconExecutorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconConsensusCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconReplicationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::runtime::BeaconSynchronizationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCoreCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelUniverseCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelTopologyCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDispatcherCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelExecutorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCoordinatorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCompositionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelResolverCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelAdmissionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelNegotiationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelObservationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelVerificationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelPersistenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelLifecycleCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelIdentityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelAuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelContractsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelInvariantsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelEvidenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelPoliciesCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDecisionsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelGoalsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelPlannerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelReasonerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelKnowledgeCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelMemoryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelRealityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCapabilitiesCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelResourcesCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelExecutionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCertificationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelGenerationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelBootstrapCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelManifestCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDescriptorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelMetadataCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelNamespaceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelTypeSystemCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelABICapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelLoaderCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelEmitterCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelSerializerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDeserializerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelMigrationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelCompatibilityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDiagnosticsCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelProfilerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelOptimizerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelHotPatchCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelRecoveryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelReplayCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelSnapshotCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelSealCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelRootCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelHostCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelPlatformCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelEnvironmentCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelConfigurationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelBootCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelSessionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelWorkspaceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelProjectCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelArtifactCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelModuleCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelPackageCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelImageCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelProcessCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelThreadCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelFiberCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelDeviceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelServiceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::kernel::KernelRootAuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GoalEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::DecisionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::EvidenceGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ReasoningGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::PlanningGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ContextGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::WorldStateGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ConfidenceEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ConsistencyEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::QualityEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ConstraintGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::CapabilityArbitratorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationOrchestratorCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::RealityGraphCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::UniversalCapabilityRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ModelAdmissionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ModelCapabilityEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ModelTranslationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::InferenceKernelCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::InferenceSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::InferencePlannerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::TensorRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::TensorSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::TensorMemoryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::OperationRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::OperationSchedulerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::OperationFusionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GraphOptimizerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::KernelFusionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::AttentionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::MoEEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::KVEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::TokenizerEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::SamplingEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::DecodeEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::StreamEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::KnowledgeEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::MemoryEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::LearningEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::SelfImprovementEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ReflectionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::HypothesisEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::SimulationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::PredictionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::OptimizationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::CompositionEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::AdaptationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::CoordinationEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationKernelCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationAuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::ExternalOracleRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleSubjectCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleEvidenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleComparisonCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleTruthEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleIsolationCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleDeterminismCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleLogitsParityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleHiddenParityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleCheckpointRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleReceiptCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::CertificationAuthorityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::SubjectFreezeEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::SubjectFingerprintCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::EvidenceChainCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::IndependentProbeCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleExecutionCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleStateCaptureCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::NumericalTruthEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::StructuralTruthEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::ConstraintTruthEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::TruthConsensusEngineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::CertificationLedgerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::ImmutableReceiptCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::AuthorityPipelineCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::TruthRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::OracleRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::SubjectRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::AuthorityRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::VerdictRegistryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::certification::CertificationKernelCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationSubjectCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationLedgerCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationReplayCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationArchiveCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationHistoryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationEvidenceCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationIdentityCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationStateCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationManifestCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationContractCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::GenerationAuthorityBoundaryCapability>());
    registry.registerCapability(std::make_unique<rawrxd::generation::ProducerBoundaryCapability>());
}

} // namespace rawrxd::runtime
