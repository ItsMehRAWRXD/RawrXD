#include "ide/IDEEntry.hpp"
#include "ide/SovereignSelfCheckPanel.hpp"
#include "ide/SystemHealthIndicator.hpp"
#include "ide/HotkeySystem.hpp"
#include "ide/DockingLayout.hpp"
#include "ide/PanelState.hpp"
#include "ide/StatusBar.hpp"
#include "ide/FabricLatencyGraph.hpp"
#include "ide/NodeRing.hpp"
#include "ide/FabricLinkHeatmap.hpp"
#include "ide/NodeLoadBars.hpp"
#include "ide/RoutingConfidenceGauge.hpp"
#include "ide/FabricEventLog.hpp"
#include "ide/ErrorTracebackPanel.hpp"
#include "ide/ConsensusVoteVisualizer.hpp"
#include "ide/LatencySpikeDetector.hpp"
#include "ide/StressTestPanel.hpp"
#include "ide/PerformanceProfilerPanel.hpp"
#include "ide/MemoryLeakDetectorPanel.hpp"
#include "ide/ProtocolAnalyzerPanel.hpp"
#include "ide/PacketTraceVisualizer.hpp"
#include "ide/FabricMessageInspector.hpp"
#include "ide/EncryptionMonitorPanel.hpp"
#include "ide/KeyExchangeVisualizer.hpp"
#include "ide/SecureChannelIntegrityPanel.hpp"
#include "ide/ChaosControlPanel.hpp"
#include "ide/EmergencePanel.hpp"
#include "ide/MetaStabilityPanel.hpp"
#include "ide/IdentityPanel.hpp"
#include "ide/TemporalPanel.hpp"
#include "ide/CausalPanel.hpp"
#include "ide/IntentPanel.hpp"
#include "ide/PredictionPanel.hpp"
#include "ide/LearningPanel.hpp"
#include "ide/ExecutivePanel.hpp"
#include "ide/ValuesPanel.hpp"
#include "ide/ReflectionPanel.hpp"
#include "ide/CommunicationPanel.hpp"
#include "ide/SocialPanel.hpp"
#include "ide/CreativityPanel.hpp"
#include "ide/EthicsPanel.hpp"
#include "ide/WisdomPanel.hpp"
#include "ide/MetaCognitionPanel.hpp"
#include "ide/MasteryPanel.hpp"
#include "ide/QuantumPanel.hpp"
#include "ide/ResiliencePanel.hpp"
#include "ide/ObservabilityPanel.hpp"
#include "ide/SecurityPanel.hpp"
#include "ide/GovernancePanel.hpp"
#include "ide/ResourcePanel.hpp"
#include "ide/ScalabilityPanel.hpp"
#include "ide/FederationPanel.hpp"
#include "ide/SocietyPanel.hpp"
#include "ide/TeleologyPanel.hpp"
#include "ide/KnowledgePanel.hpp"
#include "ide/SpiritualityPanel.hpp"
#include "ide/UnityPanel.hpp"
#include "ide/ConsciousnessPanel.hpp"
#include "ide/GalacticPanel.hpp"
#include "ide/CosmicWebPanel.hpp"
#include "ide/SuperclusterGovernancePanel.hpp"
#include "sovereign/AutoRecovery.hpp"
#include "tests/FabricStressTester.hpp"

void IDEEntry::Init() {
    // Initialize core systems
    HotkeySystem::Init();
    DockingLayout::Init();
    PanelState::Init();
    StatusBar::Init();
    
    // Initialize all panels
    SovereignSelfCheckPanel::Init();
    FabricLatencyGraph::Init();
    NodeRing::Init();
    FabricLinkHeatmap::Init();
    NodeLoadBars::Init();
    RoutingConfidenceGauge::Init();
    FabricEventLog::Init();
    ErrorTracebackPanel::Init();
    ConsensusVoteVisualizer::Init();
    LatencySpikeDetector::Init();
    StressTestPanel::Init();
    PerformanceProfilerPanel::Init();
    MemoryLeakDetectorPanel::Init();
    ProtocolAnalyzerPanel::Init();
    PacketTraceVisualizer::Init();
    FabricMessageInspector::Init();
    EncryptionMonitorPanel::Init();
    KeyExchangeVisualizer::Init();
    SecureChannelIntegrityPanel::Init();
    ChaosControlPanel::Init();
    EmergencePanel::Init();
    MetaStabilityPanel::Init();
    IdentityPanel::Init();
    TemporalPanel::Init();
    CausalPanel::Init();
    IntentPanel::Init();
    PredictionPanel::Init();
    LearningPanel::Init();
    ExecutivePanel::Init();
    ValuesPanel::Init();
    ReflectionPanel::Init();
    CommunicationPanel::Init();
    SocialPanel::Init();
    CreativityPanel::Init();
    EthicsPanel::Init();
    WisdomPanel::Init();
    MetaCognitionPanel::Init();
    MasteryPanel::Init();
    QuantumPanel::Init();
    ResiliencePanel::Init();
    ObservabilityPanel::Init();
    SecurityPanel::Init();
    GovernancePanel::Init();
    ResourcePanel::Init();
    ScalabilityPanel::Init();
    FederationPanel::Init();
    SocietyPanel::Init();
    TeleologyPanel::Init();
    KnowledgePanel::Init();
    SpiritualityPanel::Init();
    UnityPanel::Init();
    ConsciousnessPanel::Init();
    GalacticPanel::Init();
    CosmicWebPanel::Init();
    SuperclusterGovernancePanel::Init();

    // Initialize sovereign systems
    AutoRecovery::Init();
    FabricStressTester::Init();
    
    // Register hotkeys
    HotkeySystem::RegisterShift("F12", [](){ SovereignSelfCheckPanel::Toggle(); });
    HotkeySystem::Register("F7", [](){ FabricLatencyGraph::Toggle(); });
    HotkeySystem::Register("F8", [](){ NodeRing::Toggle(); });
    HotkeySystem::Register("F4", [](){ FabricLinkHeatmap::Toggle(); });
    HotkeySystem::Register("F5", [](){ NodeLoadBars::Toggle(); });
    HotkeySystem::Register("F6", [](){ RoutingConfidenceGauge::Toggle(); });
    HotkeySystem::Register("F3", [](){ FabricEventLog::Toggle(); });
    HotkeySystem::Register("F2", [](){ ErrorTracebackPanel::Toggle(); });
    HotkeySystem::Register("F1", [](){ ConsensusVoteVisualizer::Toggle(); });
    HotkeySystem::Register("F9", [](){ LatencySpikeDetector::Toggle(); });
    HotkeySystem::Register("F10", [](){ StressTestPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F1", [](){ PerformanceProfilerPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F2", [](){ MemoryLeakDetectorPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F3", [](){ ProtocolAnalyzerPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F4", [](){ PacketTraceVisualizer::Toggle(); });
    HotkeySystem::Register("Ctrl+F5", [](){ FabricMessageInspector::Toggle(); });
    HotkeySystem::Register("Ctrl+F6", [](){ EncryptionMonitorPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F7", [](){ KeyExchangeVisualizer::Toggle(); });
    HotkeySystem::Register("Ctrl+F8", [](){ SecureChannelIntegrityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+F9", [](){ ChaosControlPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F11", [](){ EmergencePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F12", [](){ MetaStabilityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F12", [](){ IdentityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F8", [](){ TemporalPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F7", [](){ CausalPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F6", [](){ IntentPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F5", [](){ PredictionPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F4", [](){ LearningPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F3", [](){ ExecutivePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F2", [](){ ValuesPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F1", [](){ ReflectionPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F1", [](){ CommunicationPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F2", [](){ SocialPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F3", [](){ CreativityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F4", [](){ EthicsPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F5", [](){ WisdomPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F6", [](){ MetaCognitionPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F7", [](){ MasteryPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F8", [](){ QuantumPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F9", [](){ ResiliencePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F10", [](){ ObservabilityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F11", [](){ SecurityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Alt+F12", [](){ GovernancePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F10", [](){ ResourcePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F9", [](){ ScalabilityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F8", [](){ FederationPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F6", [](){ SocietyPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F7", [](){ TeleologyPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F5", [](){ KnowledgePanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F4", [](){ SpiritualityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F3", [](){ UnityPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F2", [](){ ConsciousnessPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F25", [](){ GalacticPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F26", [](){ CosmicWebPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+F27", [](){ SuperclusterGovernancePanel::Toggle(); });

    // Register panels in docking layout
    DockingLayout::Add(SovereignSelfCheckPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(FabricLatencyGraph::Id(), DockingLayout::Bottom);
    DockingLayout::Add(NodeRing::Id(), DockingLayout::Left);
    DockingLayout::Add(FabricLinkHeatmap::Id(), DockingLayout::Right);
    DockingLayout::Add(NodeLoadBars::Id(), DockingLayout::Bottom);
    DockingLayout::Add(RoutingConfidenceGauge::Id(), DockingLayout::Right);
    DockingLayout::Add(FabricEventLog::Id(), DockingLayout::Bottom);
    DockingLayout::Add(ErrorTracebackPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(ConsensusVoteVisualizer::Id(), DockingLayout::Center);
    DockingLayout::Add(LatencySpikeDetector::Id(), DockingLayout::Right);
    DockingLayout::Add(StressTestPanel::Id(), DockingLayout::Bottom);
    DockingLayout::Add(PerformanceProfilerPanel::Id(), DockingLayout::Bottom);
    DockingLayout::Add(MemoryLeakDetectorPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ProtocolAnalyzerPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(PacketTraceVisualizer::Id(), DockingLayout::Bottom);
    DockingLayout::Add(FabricMessageInspector::Id(), DockingLayout::Right);
    DockingLayout::Add(EncryptionMonitorPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(KeyExchangeVisualizer::Id(), DockingLayout::Bottom);
    DockingLayout::Add(SecureChannelIntegrityPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(EmergencePanel::Id(), DockingLayout::Top);
    DockingLayout::Add(ChaosControlPanel::Id(), DockingLayout::Center);
    DockingLayout::Add(IdentityPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(MetaStabilityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(TemporalPanel::Id(), DockingLayout::Bottom);
    DockingLayout::Add(CausalPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(IntentPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(PredictionPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(LearningPanel::Id(), DockingLayout::Bottom);
    DockingLayout::Add(ExecutivePanel::Id(), DockingLayout::Left);
    DockingLayout::Add(ValuesPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ReflectionPanel::Id(), DockingLayout::Center);
    DockingLayout::Add(CommunicationPanel::Id(), DockingLayout::Bottom);
    DockingLayout::Add(SocialPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(CreativityPanel::Id(), DockingLayout::Left);
    DockingLayout::Add(EthicsPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(WisdomPanel::Id(), DockingLayout::Center);
    DockingLayout::Add(MetaCognitionPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(MasteryPanel::Id(), DockingLayout::Center);
    DockingLayout::Add(QuantumPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ResiliencePanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ObservabilityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(SecurityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(GovernancePanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ResourcePanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ScalabilityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(FederationPanel::Id(), DockingLayout::Top);
    DockingLayout::Add(SocietyPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(TeleologyPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(KnowledgePanel::Id(), DockingLayout::Right);
    DockingLayout::Add(SpiritualityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(UnityPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(ConsciousnessPanel::Id(), DockingLayout::Center);
    DockingLayout::Add(GalacticPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(CosmicWebPanel::Id(), DockingLayout::Right);
    DockingLayout::Add(SuperclusterGovernancePanel::Id(), DockingLayout::Right);

    // Apply layout
    DockingLayout::Apply();
}

void IDEEntry::Render() {
    // Render status bar first (always visible)
    StatusBar::Render();
    
    // Render health indicator
    SystemHealthIndicator::Render();
    
    // Render all panels
    if (PanelState::IsVisible(SovereignSelfCheckPanel::Id())) SovereignSelfCheckPanel::Render();
    if (PanelState::IsVisible(FabricLatencyGraph::Id())) FabricLatencyGraph::Render();
    if (PanelState::IsVisible(NodeRing::Id())) NodeRing::Render();
    if (PanelState::IsVisible(FabricLinkHeatmap::Id())) FabricLinkHeatmap::Render();
    if (PanelState::IsVisible(NodeLoadBars::Id())) NodeLoadBars::Render();
    if (PanelState::IsVisible(RoutingConfidenceGauge::Id())) RoutingConfidenceGauge::Render();
    if (PanelState::IsVisible(FabricEventLog::Id())) FabricEventLog::Render();
    if (PanelState::IsVisible(ErrorTracebackPanel::Id())) ErrorTracebackPanel::Render();
    if (PanelState::IsVisible(ConsensusVoteVisualizer::Id())) ConsensusVoteVisualizer::Render();
    if (PanelState::IsVisible(LatencySpikeDetector::Id())) LatencySpikeDetector::Render();
    if (PanelState::IsVisible(StressTestPanel::Id())) StressTestPanel::Render();
    if (PanelState::IsVisible(PerformanceProfilerPanel::Id())) PerformanceProfilerPanel::Render();
    if (PanelState::IsVisible(MemoryLeakDetectorPanel::Id())) MemoryLeakDetectorPanel::Render();
    if (PanelState::IsVisible(ProtocolAnalyzerPanel::Id())) ProtocolAnalyzerPanel::Render();
    if (PanelState::IsVisible(PacketTraceVisualizer::Id())) PacketTraceVisualizer::Render();
    if (PanelState::IsVisible(FabricMessageInspector::Id())) FabricMessageInspector::Render();
    if (PanelState::IsVisible(EncryptionMonitorPanel::Id())) EncryptionMonitorPanel::Render();
    if (PanelState::IsVisible(KeyExchangeVisualizer::Id())) KeyExchangeVisualizer::Render();
    if (PanelState::IsVisible(SecureChannelIntegrityPanel::Id())) SecureChannelIntegrityPanel::Render();
    if (PanelState::IsVisible(EmergencePanel::Id())) EmergencePanel::Render();
    if (PanelState::IsVisible(ChaosControlPanel::Id())) ChaosControlPanel::Render();
    if (PanelState::IsVisible(MetaStabilityPanel::Id())) MetaStabilityPanel::Render();
    if (PanelState::IsVisible(IdentityPanel::Id())) IdentityPanel::Render();
    if (PanelState::IsVisible(TemporalPanel::Id())) TemporalPanel::Render();
    if (PanelState::IsVisible(CausalPanel::Id())) CausalPanel::Render();
    if (PanelState::IsVisible(IntentPanel::Id())) IntentPanel::Render();
    if (PanelState::IsVisible(PredictionPanel::Id())) PredictionPanel::Render();
    if (PanelState::IsVisible(LearningPanel::Id())) LearningPanel::Render();
    if (PanelState::IsVisible(ExecutivePanel::Id())) ExecutivePanel::Render();
    if (PanelState::IsVisible(ValuesPanel::Id())) ValuesPanel::Render();
    if (PanelState::IsVisible(ReflectionPanel::Id())) ReflectionPanel::Render();
    if (PanelState::IsVisible(CommunicationPanel::Id())) CommunicationPanel::Render();
    if (PanelState::IsVisible(SocialPanel::Id())) SocialPanel::Render();
    if (PanelState::IsVisible(CreativityPanel::Id())) CreativityPanel::Render();
    if (PanelState::IsVisible(EthicsPanel::Id())) EthicsPanel::Render();
    if (PanelState::IsVisible(WisdomPanel::Id())) WisdomPanel::Render();
    if (PanelState::IsVisible(MetaCognitionPanel::Id())) MetaCognitionPanel::Render();
    if (PanelState::IsVisible(MasteryPanel::Id())) MasteryPanel::Render();
    if (PanelState::IsVisible(QuantumPanel::Id())) QuantumPanel::Render();
    if (PanelState::IsVisible(ResiliencePanel::Id())) ResiliencePanel::Render();
    if (PanelState::IsVisible(ObservabilityPanel::Id())) ObservabilityPanel::Render();
    if (PanelState::IsVisible(SecurityPanel::Id())) SecurityPanel::Render();
    if (PanelState::IsVisible(GovernancePanel::Id())) GovernancePanel::Render();
    if (PanelState::IsVisible(ResourcePanel::Id())) ResourcePanel::Render();
    if (PanelState::IsVisible(ScalabilityPanel::Id())) ScalabilityPanel::Render();
    if (PanelState::IsVisible(FederationPanel::Id())) FederationPanel::Render();
    if (PanelState::IsVisible(SocietyPanel::Id())) SocietyPanel::Render();
    if (PanelState::IsVisible(TeleologyPanel::Id())) TeleologyPanel::Render();
    if (PanelState::IsVisible(KnowledgePanel::Id())) KnowledgePanel::Render();
    if (PanelState::IsVisible(SpiritualityPanel::Id())) SpiritualityPanel::Render();
    if (PanelState::IsVisible(UnityPanel::Id())) UnityPanel::Render();
    if (PanelState::IsVisible(ConsciousnessPanel::Id())) ConsciousnessPanel::Render();
    if (PanelState::IsVisible(GalacticPanel::Id())) GalacticPanel::Render();
    if (PanelState::IsVisible(CosmicWebPanel::Id())) CosmicWebPanel::Render();
    if (PanelState::IsVisible(SuperclusterGovernancePanel::Id())) SuperclusterGovernancePanel::Render();

    // Run auto-recovery check
    AutoRecovery::CheckAndRecover();
}

void IDEEntry::Shutdown() {
    // Cleanup in reverse order
    HotkeySystem::Shutdown();
}
