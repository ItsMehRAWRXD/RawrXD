/**
 * SEGValidationCommand.cpp
 * 
 * CLI implementation for SEG validation command
 */

#include "SEGValidationCommand.hpp"
#include "../seg/SEGValidationSuite.hpp"
#include <iostream>

namespace sovereign {
namespace cli {

CommandResult SEGValidationCommand::execute(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Sovereign Execution Graph Validation                       ║\n";
    std::cout << "║     Phase B.4 Batch 5/5: End-to-End System Test                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
    
    // Run validation through CLI
    int result = Sovereign::SEGValidationCLI::Run(argc, argv);
    
    return (result == 0) ? CommandResult::Success : CommandResult::Error;
}

} // namespace cli
} // namespace sovereign
