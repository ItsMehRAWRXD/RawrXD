#include "SwarmCommand.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>

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
