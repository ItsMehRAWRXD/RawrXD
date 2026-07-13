#pragma once

#include "SovereignCLI.hpp"
#include "../swarm/SovereignSwarm.hpp"
#include "../core/ModelRegistry.h"
#include "../core/InferenceBackend.h"

namespace sovereign {
namespace cli {

// Command: swarm
// Usage: rawrxd swarm [--finish-ide] [--subsystem IDE|GUI|SEG|OS] [--cycles 243-256]
//                      [--scanner-model <model>] [--repairer-model <model>]
//                      [--extender-model <model>] [--optimizer-model <model>]
//                      [--harmonizer-model <model>] [--finalizer-model <model>]
class SwarmCommand : public ICommand {
public:
    const char* getName() const override { return "swarm"; }
    const char* getDescription() const override { 
        return "Run SovereignSwarm for IDE completion with per-role model selection"; 
    }
    CommandResult execute(int argc, char* argv[]) override;

private:
    struct SwarmOptions {
        bool finishIDE = false;
        bool finishGUI = false;
        bool finishSEG = false;
        bool finishOS = false;
        bool runCycles = false;
        uint32_t cycleStart = 243;
        uint32_t cycleEnd = 256;
        bool interactive = false;
        bool listModels = false;
        
        // Batch 250: Order - Self-organization options
        bool runOrder = false;           // Run Order cycle (Batch 250)
        bool orderDebug = false;         // Debug mode for Order topology
        bool orderMap = false;           // Display role topology map
        
        // Batch 251: Resonance - Amplification options
        bool runResonance = false;       // Run Resonance cycle (Batch 251)
        bool resonanceDebug = false;       // Debug mode for Resonance
        bool resonanceMap = false;         // Display resonance amplification map
        
        // Batch 252: Amplification - Adaptive scaling options
        bool runAmplification = false;     // Run Amplification cycle (Batch 252)
        bool amplificationDebug = false;   // Debug mode for Amplification
        bool amplificationMap = false;     // Display adaptive amplification map

        // Batch 253: Integration - Cross-subsystem coupling options
        bool runIntegration = false;       // Run Integration cycle (Batch 253)
        bool integrationDebug = false;     // Debug mode for Integration
        bool integrationMap = false;       // Display cross-subsystem integration map

        // Batch 254: Convergence - Alignment toward optimal states options
        bool runConvergence = false;       // Run Convergence cycle (Batch 254)
        bool convergenceDebug = false;     // Debug mode for Convergence
        bool convergenceMap = false;       // Display convergence map

        // Batch 255: Coherence - Synchronization and mutual reinforcement options
        bool runCoherence = false;         // Run Coherence cycle (Batch 255)
        bool coherenceDebug = false;       // Debug mode for Coherence
        bool coherenceMap = false;         // Display coherence map

        // Batch 256: Harmony - Perfect unity (Unity Cycle completion) options
        bool runHarmony = false;           // Run Harmony cycle (Batch 256)
        bool harmonyDebug = false;         // Debug mode for Harmony
        bool harmonyMap = false;           // Display harmony completion map

        // Cycle 0: Emergence - Sovereign self-direction (THE FOLD) options
        bool runEmergence = false;         // Run Emergence cycle (Cycle 0)
        bool emergenceDebug = false;       // Debug mode for Emergence
        bool emergenceMap = false;         // Display emergence topology map

        // Phase A: Self Model - Learned task assignment options
        bool runSelfModel = false;         // Run Self Model phase (Phase A)
        bool learnedAssignment = false;    // Enable learned task assignment
        bool selfModelReport = false;      // Display performance report

        // Per-role model overrides
        std::string scannerModel;
        std::string repairerModel;
        std::string extenderModel;
        std::string optimizerModel;
        std::string harmonizerModel;
        std::string finalizerModel;
        std::string generalModel;
        
        // Ollama connection
        std::string ollamaHost = "http://localhost:11434";
    };
    
    SwarmOptions parseArgs(int argc, char* argv[]);
    void printUsage();
    void printRoleConfiguration(const Sovereign::SwarmAgentContext& ctx);
    bool validateModels(const SwarmOptions& opts);
    Sovereign::SwarmAgentContext buildContext(const SwarmOptions& opts);
};

} // namespace cli
} // namespace sovereign
