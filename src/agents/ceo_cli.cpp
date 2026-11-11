// ============================================================================
// ceo_cli.cpp - CEO Agent Command Line Interface
// Usage: RawrXD-CEO --continue
//        RawrXD-CEO --build ComponentName
//        RawrXD-CEO --status
// ============================================================================

#include "CEOAgent.hpp"
#include <iostream>
#include <cstring>

using namespace RawrXD::Agents;

void PrintBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    RawrXD CEO Agent                          ║
║           Autonomous Engineering Controller                  ║
╚══════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void PrintStatus(const ProjectState& state) {
    std::cout << "\n=== Project Status ===\n\n";
    
    std::cout << "✓ Completed Components:\n";
    for (const auto& comp : state.completedComponents) {
        std::cout << "  ✓ " << comp << "\n";
    }
    
    std::cout << "\n⚠ In Progress:\n";
    for (const auto& comp : state.inProgressComponents) {
        std::cout << "  ⚠ " << comp << "\n";
    }
    
    std::cout << "\n📋 Pending Tasks:\n";
    for (const auto& task : state.pendingTasks) {
        std::cout << "  📋 " << task.description << "\n";
    }
    
    if (!state.blockers.empty()) {
        std::cout << "\n❌ Blockers:\n";
        for (const auto& blocker : state.blockers) {
            std::cout << "  ❌ " << blocker << "\n";
        }
    }
    
    std::cout << "\n=== Capabilities ===\n";
    std::cout << "  Deep2 Engine:           " << (state.hasDeep2Engine ? "✓" : "✗") << "\n";
    std::cout << "  GGUF Runtime:           " << (state.hasGGUFRuntime ? "✓" : "✗") << "\n";
    std::cout << "  Execution ABI:          " << (state.hasExecutionABI ? "✓" : "✗") << "\n";
    std::cout << "  Agent Orchestrator:     " << (state.hasAgentOrchestrator ? "✓" : "✗") << "\n";
    std::cout << "  Tool Registry:          " << (state.hasToolRegistry ? "✓" : "✗") << "\n";
    std::cout << "  Telemetry:              " << (state.hasTelemetry ? "✓" : "✗") << "\n";
    std::cout << "  HotPatcher:             " << (state.hasHotPatcher ? "✓" : "✗") << "\n";
    std::cout << "  Completion Engine:      " << (state.hasCompletionEngine ? "✓" : "✗") << "\n";
    std::cout << "  Repository Intelligence:" << (state.hasRepositoryIntelligence ? "✓" : "✗") << "\n";
    std::cout << "  Model Manager:          " << (state.hasModelManager ? "✓" : "✗") << "\n";
    std::cout << "  IDE Shell:              " << (state.hasIDEShell ? "✓" : "✗") << "\n";
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  RawrXD-CEO --continue          Continue building the IDE\n";
        std::cout << "  RawrXD-CEO --build <component> Build specific component\n";
        std::cout << "  RawrXD-CEO --status             Show project status\n";
        std::cout << "  RawrXD-CEO --plan               Show implementation plan\n";
        return 1;
    }
    
    CEOAgent ceo;
    ceo.Initialize(nullptr, nullptr, nullptr);
    
    // Set up progress reporting
    ceo.SetProgressCallback([](const std::string& stage, float percent) {
        int barWidth = 50;
        int pos = static_cast<int>(barWidth * percent / 100.0f);
        
        std::cout << "\r[";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << static_cast<int>(percent) << "% " << stage;
        
        if (percent >= 100.0f) std::cout << std::endl;
        else std::cout.flush();
    });
    
    // Set up decision logging
    ceo.SetDecisionCallback([](const std::string& decision, const std::string& reason) {
        std::cout << "\n[CEO Decision] " << decision << std::endl;
        std::cout << "  Reason: " << reason << std::endl;
    });
    
    std::string command = argv[1];
    
    if (command == "--continue" || command == "-c") {
        std::cout << "\nAnalyzing current project state...\n\n";
        
        auto state = ceo.GetCurrentState();
        auto missing = ceo.GetMissingComponents();
        
        std::cout << "Recovered:\n";
        for (const auto& comp : state.completedComponents) {
            std::cout << "  ✓ " << comp << "\n";
        }
        
        if (!missing.empty()) {
            std::cout << "\nMissing product layers:\n";
            int i = 1;
            for (const auto& comp : missing) {
                std::cout << "  " << i++ << ". " << comp << "\n";
            }
            
            std::cout << "\nCreating implementation plan...\n";
            std::cout << "\nExecuting:\n";
            
            ceo.ContinueBuilding();
            
            std::cout << "\n✓ Build cycle complete\n";
        } else {
            std::cout << "\n✓ All components built. IDE is ready.\n";
        }
    }
    else if (command == "--build" || command == "-b") {
        if (argc < 3) {
            std::cerr << "Error: --build requires a component name\n";
            return 1;
        }
        std::string component = argv[2];
        std::cout << "Building component: " << component << "\n";
        ceo.BuildComponent(component);
    }
    else if (command == "--status" || command == "-s") {
        PrintStatus(ceo.GetCurrentState());
    }
    else if (command == "--plan" || command == "-p") {
        std::cout << "\n=== Implementation Plan ===\n\n";
        std::cout << "Phase 1: Foundation\n";
        std::cout << "  1. Repository Intelligence (AST indexing)\n";
        std::cout << "  2. Model Manager (lifecycle)\n";
        std::cout << "\nPhase 2: Core IDE\n";
        std::cout << "  3. Completion Engine (FIM/ghost text)\n";
        std::cout << "  4. IDE Shell (windowing)\n";
        std::cout << "\nPhase 3: Integration\n";
        std::cout << "  5. Wire to Deep2 Engine\n";
        std::cout << "  6. Telemetry integration\n";
        std::cout << "  7. HotPatch registration\n";
    }
    else {
        std::cerr << "Unknown command: " << command << "\n";
        return 1;
    }
    
    return 0;
}
