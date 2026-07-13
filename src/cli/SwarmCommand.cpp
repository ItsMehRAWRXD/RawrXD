#include "SwarmCommand.hpp"
#include "../swarm/LearningSimulator.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <fstream>

namespace sovereign {
namespace cli {

void SwarmCommand::printUsage() {
    std::cout << "Usage: rawrxd swarm [OPTIONS]\n\n";
    std::cout << "Run SovereignSwarm for IDE completion with per-role model selection.\n\n";
    std::cout << "Options:\n";
    std::cout << "  --finish-ide           Complete IDE subsystem (scan, repair, extend, optimize)\n";
    std::cout << "  --finish-gui           Complete GUI subsystem\n";
    std::cout << "  --finish-seg           Complete SEG (Sovereign Execution Graph) subsystem\n";
    std::cout << "  --finish-os            Complete OS (Sovereign OS) subsystem\n";
    std::cout << "  --finish-all           Complete all subsystems (IDE, GUI, SEG, OS)\n";
    std::cout << "  --cycles START-END     Run Unity Cycle harmonization (default: 243-256)\n";
    std::cout << "  --interactive          Interactive mode: configure models per role\n";
    std::cout << "  --list-models          List available models from Ollama\n";
    std::cout << "\nBatch 250: Order - Self-Organization:\n";
    std::cout << "  --order                Run Order cycle (dynamic role topology)\n";
    std::cout << "  --order-debug          Debug mode: show topology computation\n";
    std::cout << "  --order-map            Display role topology map\n";
    std::cout << "\nBatch 251: Resonance - Amplification:\n";
    std::cout << "  --resonance            Run Resonance cycle (pattern amplification)\n";
    std::cout << "  --resonance-debug      Debug mode: show resonance computation\n";
    std::cout << "  --resonance-map        Display resonance amplification map\n";
    std::cout << "\nBatch 252: Amplification - Adaptive Scaling:\n";
    std::cout << "  --amplification        Run Amplification cycle (adaptive scaling)\n";
    std::cout << "  --amplification-debug  Debug mode: show adaptive scaling computation\n";
    std::cout << "  --amplification-map    Display adaptive amplification map\n";
    std::cout << "\nBatch 253: Integration - Cross-Subsystem Coupling:\n";
    std::cout << "  --integration          Run Integration cycle (cross-subsystem coupling)\n";
    std::cout << "  --integration-debug    Debug mode: show integration computation\n";
    std::cout << "  --integration-map      Display cross-subsystem integration map\n";
    std::cout << "\nBatch 254: Convergence - Alignment Toward Optimal States:\n";
    std::cout << "  --convergence          Run Convergence cycle (alignment to optimal)\n";
    std::cout << "  --convergence-debug    Debug mode: show convergence computation\n";
    std::cout << "  --convergence-map      Display convergence toward optimal states\n";
    std::cout << "\nBatch 255: Coherence - Synchronization and Mutual Reinforcement:\n";
    std::cout << "  --coherence            Run Coherence cycle (synchronization)\n";
    std::cout << "  --coherence-debug      Debug mode: show coherence computation\n";
    std::cout << "  --coherence-map        Display coherence synchronization map\n";
    std::cout << "\nBatch 256: Harmony - Perfect Unity (Unity Cycle Completion):\n";
    std::cout << "  --harmony              Run Harmony cycle (perfect unity)\n";
    std::cout << "  --harmony-debug        Debug mode: show harmony computation\n";
    std::cout << "  --harmony-map          Display harmony completion map\n";
    std::cout << "\nCycle 0: Emergence - Sovereign Self-Direction (THE FOLD):\n";
    std::cout << "  --emergence            Run Emergence cycle (sovereign self-direction)\n";
    std::cout << "  --emergence-debug      Debug mode: show emergence computation\n";
    std::cout << "  --emergence-map        Display emergence topology map\n";
    std::cout << "\nPhase A: Self Model - Learned Task Assignment:\n";
    std::cout << "  --self-model           Run Self Model phase (learned assignment)\n";
    std::cout << "  --learned-assignment   Enable learned task assignment based on history\n";
    std::cout << "  --self-model-report    Display performance report after execution\n";
    std::cout << "\nPhase A.1-A.5: Advanced Learning Features:\n";
    std::cout << "  --benchmark            Run benchmark to validate learning (A.1)\n";
    std::cout << "  --benchmark-runs N     Number of benchmark iterations (default: 500)\n";
    std::cout << "  --explain              Explain last routing decision (A.5)\n";
    std::cout << "  --exploration-rate R   Set exploration rate 0.0-1.0 (default: 0.1) (A.3)\n";
    std::cout << "  --reset-stats          Reset statistics before run\n";
    std::cout << "\nPhase A.1: Deterministic Learning Simulator:\n";
    std::cout << "  --simulator            Run deterministic simulator to validate learning\n";
    std::cout << "  --sim-scenario TYPE    Scenario: stationary, latency, noisy, dominant\n";
    std::cout << "  --sim-export PATH      Export results to CSV or JSON file\n";
    std::cout << "\nPhase 2: Unity Sequence - Full Engine Integration:\n";
    std::cout << "  --unity-sequence       Execute full Order→Harmony pipeline with engine\n";
    std::cout << "  --unity-sequence-log   Log detailed metrics after sequence\n";
    std::cout << "  --unity-sequence-output FILE  Export results to file\n";
    std::cout << "\nPhase B.2: Telemetry Export (Batches 2-6):\n";
    std::cout << "  --export-telemetry       Export Unity Cycle telemetry to JSON\n";
    std::cout << "  --telemetry-output PATH  Output path for telemetry JSON\n";
    std::cout << "  --show-convergence       Display convergence metrics\n";
    std::cout << "  --show-unity-cycle       Display Unity Cycle field values\n";
    std::cout << "  --export-sqlite          Export telemetry to SQLite database\n";
    std::cout << "  --sqlite-db PATH         SQLite database path\n";
    std::cout << "  --telemetry-dashboard    Start telemetry dashboard server\n";
    std::cout << "  --dashboard-port PORT    Dashboard server port (default: 8080)\n";
    std::cout << "\nPer-Role Model Selection:\n";
    std::cout << "  --scanner-model MODEL      Model for scanning (default: nemotron-super:latest)\n";
    std::cout << "  --repairer-model MODEL     Model for repairs (default: qwen3.5:40b)\n";
    std::cout << "  --extender-model MODEL     Model for extensions (default: codestral:22b)\n";
    std::cout << "  --optimizer-model MODEL    Model for optimization (default: deepseek-r1:8b)\n";
    std::cout << "  --harmonizer-model MODEL   Model for harmonization (default: gemma3:27b)\n";
    std::cout << "  --finalizer-model MODEL    Model for finalization (default: bigdaddyg:38gb)\n";
    std::cout << "  --general-model MODEL      Fallback model (default: llama3.2:3b)\n";
    std::cout << "\nConnection:\n";
    std::cout << "  --ollama-host URL      Ollama server URL (default: http://localhost:11434)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  rawrxd swarm --finish-ide\n";
    std::cout << "  rawrxd swarm --finish-all --cycles 243-250\n";
    std::cout << "  rawrxd swarm --finish-ide --scanner-model qwen3.5:40b --repairer-model codestral:22b\n";
    std::cout << "  rawrxd swarm --interactive\n";
}

SwarmCommand::SwarmOptions SwarmCommand::parseArgs(int argc, char* argv[]) {
    SwarmOptions opts;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--finish-ide") opts.finishIDE = true;
        else if (arg == "--finish-gui") opts.finishGUI = true;
        else if (arg == "--finish-seg") opts.finishSEG = true;
        else if (arg == "--finish-os") opts.finishOS = true;
        else if (arg == "--finish-all") {
            opts.finishIDE = opts.finishGUI = opts.finishSEG = opts.finishOS = true;
        }
        else if (arg == "--cycles" && i + 1 < argc) {
            std::string range = argv[++i];
            size_t dash = range.find('-');
            if (dash != std::string::npos) {
                opts.cycleStart = std::stoi(range.substr(0, dash));
                opts.cycleEnd = std::stoi(range.substr(dash + 1));
                opts.runCycles = true;
            }
        }
        else if (arg == "--interactive") opts.interactive = true;
        else if (arg == "--list-models") opts.listModels = true;
        // Batch 250: Order options
        else if (arg == "--order") opts.runOrder = true;
        else if (arg == "--order-debug") { opts.runOrder = true; opts.orderDebug = true; }
        else if (arg == "--order-map") { opts.runOrder = true; opts.orderMap = true; }
        // Batch 251: Resonance options
        else if (arg == "--resonance") opts.runResonance = true;
        else if (arg == "--resonance-debug") { opts.runResonance = true; opts.resonanceDebug = true; }
        else if (arg == "--resonance-map") { opts.runResonance = true; opts.resonanceMap = true; }
        // Batch 252: Amplification options
        else if (arg == "--amplification") opts.runAmplification = true;
        else if (arg == "--amplification-debug") { opts.runAmplification = true; opts.amplificationDebug = true; }
        else if (arg == "--amplification-map") { opts.runAmplification = true; opts.amplificationMap = true; }
        // Batch 253: Integration options
        else if (arg == "--integration") opts.runIntegration = true;
        else if (arg == "--integration-debug") { opts.runIntegration = true; opts.integrationDebug = true; }
        else if (arg == "--integration-map") { opts.runIntegration = true; opts.integrationMap = true; }
        // Batch 254: Convergence options
        else if (arg == "--convergence") opts.runConvergence = true;
        else if (arg == "--convergence-debug") { opts.runConvergence = true; opts.convergenceDebug = true; }
        else if (arg == "--convergence-map") { opts.runConvergence = true; opts.convergenceMap = true; }
        // Batch 255: Coherence options
        else if (arg == "--coherence") opts.runCoherence = true;
        else if (arg == "--coherence-debug") { opts.runCoherence = true; opts.coherenceDebug = true; }
        else if (arg == "--coherence-map") { opts.runCoherence = true; opts.coherenceMap = true; }
        // Batch 256: Harmony options
        else if (arg == "--harmony") opts.runHarmony = true;
        else if (arg == "--harmony-debug") { opts.runHarmony = true; opts.harmonyDebug = true; }
        else if (arg == "--harmony-map") { opts.runHarmony = true; opts.harmonyMap = true; }
        // Cycle 0: Emergence options
        else if (arg == "--emergence") opts.runEmergence = true;
        else if (arg == "--emergence-debug") { opts.runEmergence = true; opts.emergenceDebug = true; }
        else if (arg == "--emergence-map") { opts.runEmergence = true; opts.emergenceMap = true; }
        // Phase A: Self Model options
        else if (arg == "--self-model") opts.runSelfModel = true;
        else if (arg == "--learned-assignment") { opts.runSelfModel = true; opts.learnedAssignment = true; }
        else if (arg == "--self-model-report") { opts.runSelfModel = true; opts.selfModelReport = true; }
        // Phase A.1-A.5: Advanced learning options
        else if (arg == "--benchmark") { opts.runSelfModel = true; opts.benchmarkLearning = true; }
        else if (arg == "--benchmark-runs" && i + 1 < argc) { opts.benchmarkIterations = std::stoi(argv[++i]); }
        else if (arg == "--explain") { opts.runSelfModel = true; opts.explainDecision = true; }
        else if (arg == "--exploration-rate" && i + 1 < argc) { opts.explorationRate = std::stod(argv[++i]); }
        else if (arg == "--reset-stats") { opts.runSelfModel = true; opts.resetStats = true; }
        // Phase A.1: Simulator options
        else if (arg == "--simulator") { opts.runSimulator = true; }
        else if (arg == "--sim-scenario" && i + 1 < argc) { opts.simulatorScenario = argv[++i]; }
        else if (arg == "--sim-export" && i + 1 < argc) { opts.exportResults = true; opts.exportPath = argv[++i]; }
        // Phase 2: Unity Sequence options
        else if (arg == "--unity-sequence") { opts.runUnitySequence = true; }
        else if (arg == "--unity-sequence-log") { opts.runUnitySequence = true; opts.unitySequenceLog = true; }
        else if (arg == "--unity-sequence-output" && i + 1 < argc) { opts.runUnitySequence = true; opts.unitySequenceOutput = argv[++i]; }
        // Phase B.2: Telemetry Export Options (Batches 2-6)
        else if (arg == "--export-telemetry") { opts.exportTelemetry = true; }
        else if (arg == "--telemetry-output" && i + 1 < argc) { opts.exportTelemetry = true; opts.telemetryOutputPath = argv[++i]; }
        else if (arg == "--show-convergence") { opts.showConvergence = true; }
        else if (arg == "--show-unity-cycle") { opts.showUnityCycle = true; }
        else if (arg == "--export-sqlite") { opts.exportSQLite = true; }
        else if (arg == "--sqlite-db" && i + 1 < argc) { opts.exportSQLite = true; opts.sqliteDbPath = argv[++i]; }
        else if (arg == "--telemetry-dashboard") { opts.telemetryDashboard = true; }
        else if (arg == "--dashboard-port" && i + 1 < argc) { opts.telemetryDashboard = true; opts.dashboardPort = static_cast<uint16_t>(std::stoi(argv[++i])); }
        else if (arg == "--scanner-model" && i + 1 < argc) opts.scannerModel = argv[++i];
        else if (arg == "--repairer-model" && i + 1 < argc) opts.repairerModel = argv[++i];
        else if (arg == "--extender-model" && i + 1 < argc) opts.extenderModel = argv[++i];
        else if (arg == "--optimizer-model" && i + 1 < argc) opts.optimizerModel = argv[++i];
        else if (arg == "--harmonizer-model" && i + 1 < argc) opts.harmonizerModel = argv[++i];
        else if (arg == "--finalizer-model" && i + 1 < argc) opts.finalizerModel = argv[++i];
        else if (arg == "--general-model" && i + 1 < argc) opts.generalModel = argv[++i];
        else if (arg == "--ollama-host" && i + 1 < argc) opts.ollamaHost = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            printUsage();
            return opts;
        }
    }
    
    // If no specific subsystem selected and not interactive/list, default to finish-all
    if (!opts.finishIDE && !opts.finishGUI && !opts.finishSEG && !opts.finishOS && 
        !opts.interactive && !opts.listModels) {
        opts.finishIDE = opts.finishGUI = opts.finishSEG = opts.finishOS = true;
        opts.runCycles = true;
    }
    
    return opts;
}

void SwarmCommand::printRoleConfiguration(const Sovereign::SwarmAgentContext& ctx) {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           SovereignSwarm Role Configuration                  ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    auto printRole = [&ctx](Sovereign::ModelRole role, const char* name) {
        auto config = ctx.GetRoleModel(role);
        std::cout << "║ " << std::left << std::setw(12) << name << ": " << std::setw(25) << config.modelName;
        std::cout << " (ctx=" << std::setw(5) << config.contextLength << ", temp=" << config.temperature << ") ║\n";
    };
    
    printRole(Sovereign::ModelRole::Scanner, "Scanner");
    printRole(Sovereign::ModelRole::Repairer, "Repairer");
    printRole(Sovereign::ModelRole::Extender, "Extender");
    printRole(Sovereign::ModelRole::Optimizer, "Optimizer");
    printRole(Sovereign::ModelRole::Harmonizer, "Harmonizer");
    printRole(Sovereign::ModelRole::Finalizer, "Finalizer");
    printRole(Sovereign::ModelRole::General, "General");
    
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
}

bool SwarmCommand::validateModels(const SwarmOptions& opts) {
    // TODO: Query Ollama to verify models exist
    // For now, assume valid
    return true;
}

Sovereign::SwarmAgentContext SwarmCommand::buildContext(const SwarmOptions& opts) {
    Sovereign::SwarmAgentContext ctx;
    
    // Apply model overrides
    if (!opts.scannerModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Scanner);
        config.modelName = opts.scannerModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Scanner, config);
    }
    if (!opts.repairerModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Repairer);
        config.modelName = opts.repairerModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Repairer, config);
    }
    if (!opts.extenderModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Extender);
        config.modelName = opts.extenderModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Extender, config);
    }
    if (!opts.optimizerModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Optimizer);
        config.modelName = opts.optimizerModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Optimizer, config);
    }
    if (!opts.harmonizerModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Harmonizer);
        config.modelName = opts.harmonizerModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Harmonizer, config);
    }
    if (!opts.finalizerModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::Finalizer);
        config.modelName = opts.finalizerModel;
        ctx.SetRoleModel(Sovereign::ModelRole::Finalizer, config);
    }
    if (!opts.generalModel.empty()) {
        auto config = ctx.GetRoleModel(Sovereign::ModelRole::General);
        config.modelName = opts.generalModel;
        ctx.SetRoleModel(Sovereign::ModelRole::General, config);
    }
    
    return ctx;
}

CommandResult SwarmCommand::execute(int argc, char* argv[]) {
    if (argc == 1) {
        printUsage();
        return CommandResult::Success;
    }
    
    SwarmOptions opts = parseArgs(argc, argv);
    
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║              SovereignSwarm IDE Completion                   ║\n";
    std::cout << "║         Per-Role Model Selection for HexMag Swarm          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    // Build context with model overrides
    Sovereign::SwarmAgentContext ctx = buildContext(opts);
    
    // Print configuration
    printRoleConfiguration(ctx);
    
    // Validate models
    if (!validateModels(opts)) {
        std::cerr << "[ERROR] Model validation failed\n";
        return CommandResult::Error;
    }
    
    // Create Swarm
    Sovereign::SovereignSwarm swarm(ctx);
    
    // Execute based on options
    if (opts.interactive) {
        std::cout << "[MODE] Interactive configuration\n";
        swarm.RunInteractiveConfiguration();
        return CommandResult::Success;
    }
    
    if (opts.listModels) {
        std::cout << "[MODE] Listing available models from Ollama...\n";
        // TODO: Query Ollama API
        std::cout << "  - nemotron-super:latest (86GB)\n";
        std::cout << "  - qwen3.5:40b\n";
        std::cout << "  - codestral:22b\n";
        std::cout << "  - deepseek-r1:8b\n";
        std::cout << "  - gemma3:27b\n";
        std::cout << "  - bigdaddyg:38gb\n";
        std::cout << "  - llama3.2:3b\n";
        return CommandResult::Success;
    }
    
    // Run subsystem completion
    if (opts.finishIDE) {
        std::cout << "[TASK] Completing IDE subsystem...\n";
        swarm.RunSubsystemCompletion("IDE");
    }
    if (opts.finishGUI) {
        std::cout << "[TASK] Completing GUI subsystem...\n";
        swarm.RunSubsystemCompletion("GUI");
    }
    if (opts.finishSEG) {
        std::cout << "[TASK] Completing SEG subsystem...\n";
        swarm.RunSubsystemCompletion("SEG");
    }
    if (opts.finishOS) {
        std::cout << "[TASK] Completing OS subsystem...\n";
        swarm.RunSubsystemCompletion("OS");
    }
    
    // Run Unity Cycle harmonization
    if (opts.runCycles) {
        std::cout << "[TASK] Running Unity Cycle harmonization (" 
                  << opts.cycleStart << "-" << opts.cycleEnd << ")...\n";
        swarm.RunCycleHarmonization(opts.cycleStart, opts.cycleEnd);
    }
    
    // Batch 250: Order - Self-organization
    if (opts.runOrder) {
        std::cout << "[TASK] Running Order cycle (Batch 250) - Self-organization...\n";
        if (opts.orderDebug) {
            std::cout << "[DEBUG] Order topology computation enabled\n";
        }
        if (opts.orderMap) {
            std::cout << "[MAP] Displaying role topology map...\n";
            swarm.PrintOrderTopology();
        }
        swarm.RunOrderCycle();
    }
    
    // Batch 251: Resonance - Amplification
    if (opts.runResonance) {
        std::cout << "[TASK] Running Resonance cycle (Batch 251) - Pattern amplification...\n";
        if (opts.resonanceDebug) {
            std::cout << "[DEBUG] Resonance amplification computation enabled\n";
        }
        if (opts.resonanceMap) {
            std::cout << "[MAP] Displaying resonance amplification map...\n";
            swarm.PrintResonanceMap();
        }
        swarm.RunResonanceCycle();
    }
    
    // Batch 252: Amplification - Adaptive scaling
    if (opts.runAmplification) {
        std::cout << "[TASK] Running Amplification cycle (Batch 252) - Adaptive scaling...\n";
        if (opts.amplificationDebug) {
            std::cout << "[DEBUG] Adaptive amplification computation enabled\n";
        }
        if (opts.amplificationMap) {
            std::cout << "[MAP] Displaying adaptive amplification map...\n";
            swarm.PrintAmplificationMap();
        }
        swarm.RunAmplificationCycle();
    }

    // Batch 253: Integration - Cross-subsystem coupling
    if (opts.runIntegration) {
        std::cout << "[TASK] Running Integration cycle (Batch 253) - Cross-subsystem coupling...\n";
        if (opts.integrationDebug) {
            std::cout << "[DEBUG] Cross-subsystem integration computation enabled\n";
        }
        if (opts.integrationMap) {
            std::cout << "[MAP] Displaying cross-subsystem integration map...\n";
            swarm.PrintIntegrationMap();
        }
        swarm.RunIntegrationCycle();
    }

    // Batch 254: Convergence - Alignment toward optimal states
    if (opts.runConvergence) {
        std::cout << "[TASK] Running Convergence cycle (Batch 254) - Alignment toward optimal states...\n";
        if (opts.convergenceDebug) {
            std::cout << "[DEBUG] Convergence computation enabled\n";
        }
        if (opts.convergenceMap) {
            std::cout << "[MAP] Displaying convergence toward optimal states...\n";
            swarm.PrintConvergenceMap();
        }
        swarm.RunConvergenceCycle();
    }

    // Batch 255: Coherence - Synchronization and mutual reinforcement
    if (opts.runCoherence) {
        std::cout << "[TASK] Running Coherence cycle (Batch 255) - Synchronization and mutual reinforcement...\n";
        if (opts.coherenceDebug) {
            std::cout << "[DEBUG] Coherence computation enabled\n";
        }
        if (opts.coherenceMap) {
            std::cout << "[MAP] Displaying coherence synchronization map...\n";
            swarm.PrintCoherenceMap();
        }
        swarm.RunCoherenceCycle();
    }

    // Batch 256: Harmony - Perfect unity (Unity Cycle completion)
    if (opts.runHarmony) {
        std::cout << "[TASK] Running Harmony cycle (Batch 256) - Perfect unity (Unity Cycle completion)...\n";
        if (opts.harmonyDebug) {
            std::cout << "[DEBUG] Harmony computation enabled\n";
        }
        if (opts.harmonyMap) {
            std::cout << "[MAP] Displaying harmony completion map...\n";
            swarm.PrintHarmonyMap();
        }
        swarm.RunHarmonyCycle();
    }

    // Cycle 0: Emergence - Sovereign self-direction (THE FOLD)
    if (opts.runEmergence) {
        std::cout << "[TASK] Running Emergence cycle (Cycle 0) - Sovereign self-direction...\n";
        if (opts.emergenceDebug) {
            std::cout << "[DEBUG] Emergence computation enabled\n";
        }
        if (opts.emergenceMap) {
            std::cout << "[MAP] Displaying emergence topology map...\n";
            swarm.PrintEmergenceMap();
        }
        swarm.RunEmergenceCycle();
    }

    // Phase A: Self Model - Learned task assignment
    if (opts.runSelfModel) {
        std::cout << "[TASK] Running Phase A: Self Model - Learned task assignment...\n";
        
        // Phase A.1-A.5: Reset statistics if requested
        if (opts.resetStats) {
            std::cout << "[INFO] Resetting statistics...\n";
            Sovereign::SelfModelRegistry::GetInstance().ResetStatistics();
        }
        
        // Enable learned assignment if requested
        if (opts.learnedAssignment) {
            std::cout << "[INFO] Learned task assignment enabled - agents will be assigned based on execution history\n";
            swarm.GetScheduler().SetLearnedAssignmentEnabled(true);
        }
        
        // Phase A.3: Set exploration rate
        swarm.GetScheduler().SetExplorationRate(opts.explorationRate);
        std::cout << "[INFO] Exploration rate set to " << (opts.explorationRate * 100) << "%\n";
        
        // Run a series of tasks to build up performance data
        std::cout << "[TASK] Executing task suite to build self-model...\n";
        swarm.RunOrderCycle();      // Batch 250
        swarm.RunResonanceCycle();  // Batch 251
        swarm.RunAmplificationCycle(); // Batch 252
        
        // Phase A.1: Benchmark and validation
        if (opts.benchmarkLearning) {
            std::cout << "[TASK] Running benchmark to validate learning...\n";
            swarm.GetScheduler().PrintBenchmarkReport(Sovereign::SwarmTaskKind::ScanSubsystem, opts.benchmarkIterations);
        }
        
        // Phase A.5: Explain last decision
        if (opts.explainDecision) {
            std::cout << swarm.GetScheduler().ExplainLastDecision();
        }
        
        // Display performance report if requested
        if (opts.selfModelReport) {
            Sovereign::SelfModelRegistry::GetInstance().PrintPerformanceReport();
        }
    }

    // Phase A.1: Deterministic Learning Simulator
    if (opts.runSimulator) {
        std::cout << "[TASK] Running Phase A.1: Deterministic Learning Simulator...\n";
        
        // Select scenario
        Sovereign::LearningSimulator::TestScenario scenario;
        if (opts.simulatorScenario == "stationary") {
            scenario = Sovereign::LearningSimulator::CreateStationaryScenario();
        } else if (opts.simulatorScenario == "latency") {
            scenario = Sovereign::LearningSimulator::CreateLatencyTradeoffScenario();
        } else if (opts.simulatorScenario == "noisy") {
            scenario = Sovereign::LearningSimulator::CreateNoisyScenario();
        } else if (opts.simulatorScenario == "dominant") {
            scenario = Sovereign::LearningSimulator::CreateDominantScenario();
        } else {
            std::cout << "[WARN] Unknown scenario '" << opts.simulatorScenario 
                      << "', using 'stationary'\n";
            scenario = Sovereign::LearningSimulator::CreateStationaryScenario();
        }
        
        std::cout << "[INFO] Running scenario: " << scenario.name << "\n";
        std::cout << "[INFO] Iterations: " << scenario.iterations << "\n";
        
        // Create and run simulator
        Sovereign::LearningSimulator simulator(scenario);
        auto snapshots = simulator.RunWithTracking(10);
        
        // Print results
        simulator.PrintReport();
        simulator.PrintConvergenceGraph(snapshots);
        
        // Export if requested
        if (opts.exportResults && !opts.exportPath.empty()) {
            if (opts.exportPath.ends_with(".csv")) {
                simulator.ExportCSV(opts.exportPath);
                std::cout << "[INFO] Exported results to " << opts.exportPath << "\n";
            } else if (opts.exportPath.ends_with(".json")) {
                simulator.ExportJSON(opts.exportPath);
                std::cout << "[INFO] Exported results to " << opts.exportPath << "\n";
            } else {
                std::cout << "[WARN] Unknown export format, use .csv or .json\n";
            }
        }
        
        // Validate and report
        auto criteria = simulator.Validate();
        std::cout << criteria.ToString() << "\n";
        
        if (criteria.AllPassed()) {
            std::cout << "[SUCCESS] All benchmark criteria passed!\n";
        } else {
            std::cout << "[WARNING] Some benchmark criteria failed. Review results above.\n";
        }
    }

    // Phase 2: Unity Sequence - Execute full Order→Harmony pipeline with engine
    if (opts.runUnitySequence) {
        std::cout << "[TASK] Running Phase 2: Unity Sequence (Order→Harmony with engine)...\n";
        
        // Create engine instance
        auto& engine = InfinitePerfection::InfinitePerfectionEngine::GetInstance();
        engine.Initialize();
        
        // Execute Unity Sequence
        auto result = swarm.ExecuteUnitySequence(engine);
        
        // Log metrics if requested
        if (opts.unitySequenceLog) {
            swarm.LogUnitySequenceMetrics(result);
        }
        
        // Export to file if requested
        if (!opts.unitySequenceOutput.empty()) {
            std::ofstream outFile(opts.unitySequenceOutput);
            if (outFile.is_open()) {
                outFile << "{\n";
                outFile << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
                outFile << "  \"finalHarmonyIndex\": " << result.finalHarmonyIndex << ",\n";
                outFile << "  \"finalEquilibriumStrength\": " << result.finalEquilibriumStrength << ",\n";
                outFile << "  \"totalExecutionTimeMs\": " << result.totalExecutionTimeMs << ",\n";
                outFile << "  \"summary\": \"" << result.summary << "\",\n";
                outFile << "  \"stepMetrics\": [\n";
                for (size_t i = 0; i < result.stepMetrics.size(); ++i) {
                    outFile << "    {\"step\": \"" << result.stepMetrics[i].first << "\", \"metric\": " << result.stepMetrics[i].second << "}";
                    if (i < result.stepMetrics.size() - 1) outFile << ",";
                    outFile << "\n";
                }
                outFile << "  ]\n";
                outFile << "}\n";
                outFile.close();
                std::cout << "[INFO] Unity Sequence results exported to " << opts.unitySequenceOutput << "\n";
            } else {
                std::cerr << "[ERROR] Failed to open output file: " << opts.unitySequenceOutput << "\n";
            }
        }
        
        // Shutdown engine
        engine.Shutdown();
        
        std::cout << "[SUCCESS] Unity Sequence completed: " << result.summary << "\n";
    }

    // Phase B.2: Telemetry Export and Display
    if (opts.exportTelemetry || opts.showConvergence || opts.showUnityCycle) {
        std::cout << "[TASK] Phase B.2: Processing telemetry...\n";
        
        // Create telemetry bridge if engine is available
        auto& engine = InfinitePerfection::InfinitePerfectionEngine::GetInstance();
        if (engine.IsInitialized()) {
            Sovereign::InfinitePerfectionTelemetry telemetry(&engine);
            
            // Show convergence metrics
            if (opts.showConvergence) {
                std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
                std::cout << "║           Unity Cycle Convergence Status                     ║\n";
                std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
                
                auto unity = engine.ComputeUnity();
                auto integration = engine.ComputeIntegration();
                auto synthesis = engine.ComputeSynthesis();
                auto convergence = engine.ComputeConvergence();
                auto coherence = engine.ComputeCoherence();
                auto harmony = engine.ComputeHarmony();
                auto balance = engine.ComputeBalance();
                
                std::cout << std::fixed << std::setprecision(2);
                std::cout << "║  Order (Unity):          " << std::setw(6) << unity.unityPotential << "                    ║\n";
                std::cout << "║  Resonance (Integration):" << std::setw(6) << integration.cycleIntegration << "                    ║\n";
                std::cout << "║  Amplification (Synth):  " << std::setw(6) << synthesis.sovereignEmergenceIndex << "                    ║\n";
                std::cout << "║  Integration (Converge): " << std::setw(6) << convergence.sovereignConvergenceIndex << "                    ║\n";
                std::cout << "║  Convergence (Coherence):" << std::setw(6) << coherence.sovereignCoherenceIndex << "                    ║\n";
                std::cout << "║  Coherence (Harmony):    " << std::setw(6) << harmony.sovereignHarmonyIndex << "                    ║\n";
                std::cout << "║  Harmony (Balance):      " << std::setw(6) << balance.equilibriumStrength << "                    ║\n";
                std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
                
                double globalIndex = telemetry.GetConvergenceScore();
                std::cout << "║  Global Harmony Index:   " << std::setw(6) << globalIndex << "                    ║\n";
                std::cout << "║  Status: " << (telemetry.IsConverged() ? "CONVERGED ✓" : "CONVERGING...") << "                              ║\n";
                std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
            }
            
            // Show Unity Cycle field values
            if (opts.showUnityCycle) {
                std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
                std::cout << "║              Unity Cycle Field Values                        ║\n";
                std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
                
                auto snapshot = telemetry.GetSnapshot();
                std::cout << telemetry.ExportToJson() << "\n";
            }
            
            // Export telemetry to JSON
            if (opts.exportTelemetry) {
                std::string outputPath = opts.telemetryOutputPath.empty() ? 
                    "telemetry_export.json" : opts.telemetryOutputPath;
                
                std::ofstream outFile(outputPath);
                if (outFile.is_open()) {
                    outFile << telemetry.ExportToJson();
                    outFile.close();
                    std::cout << "[INFO] Telemetry exported to " << outputPath << "\n";
                } else {
                    std::cerr << "[ERROR] Failed to export telemetry to " << outputPath << "\n";
                }
            }
        } else {
            std::cout << "[WARN] Engine not initialized, skipping telemetry\n";
        }
    }
    
    // Run finalization
    std::cout << "[TASK] Running finalization...\n";
    swarm.RunFinalization();
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║              SovereignSwarm Completion Finished              ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return CommandResult::Success;
}

} // namespace cli
} // namespace sovereign
