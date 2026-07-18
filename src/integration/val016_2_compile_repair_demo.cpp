/*---------------------------------------------------------------------------------------------
 *  VAL-016.2: Compile Failure Repair Demonstration
 *  
 *  Purpose: Demonstrate source-level autonomous repair from CompileFailed failure.
 *  
 *  Scenario:
 *    1. Create broken.cpp with missing semicolon
 *    2. Compile (fails with C2143)
 *    3. Parse diagnostic
 *    4. Generate repair plan (insert semicolon)
 *    5. Apply patch
 *    6. Rebuild (succeeds)
 *  
 *  Evidence Structure:
 *    validation/val-016-2/
 *    ├── input/
 *    │   └── broken.cpp          # Source with intentional defect
 *    ├── execution/
 *    │   ├── first_attempt.json  # Initial ExecutionResult
 *    │   ├── compiler_output.txt # Raw compiler output
 *    │   └── retry_attempt.json  # Post-repair ExecutionResult
 *    ├── repair/
 *    │   ├── diagnostics.json    # Structured CompilerDiagnostic[]
 *    │   ├── repair_plan.json    # RepairPlan with confidence
 *    │   ├── patch.json          # RepairPatch metadata
 *    │   ├── patch.diff          # Unified diff format
 *    │   └── repair_attempts.jsonl # Append-only history
 *    └── result/
 *        ├── trace.json          # Complete lifecycle trace
 *        └── completion.json     # VAL-016 completion certificate
 *--------------------------------------------------------------------------------------------*/

#include "val016_repair_orchestrator.h"
#include <iostream>

using namespace RawrXD::VAL016;

int main(int argc, char* argv[]) {
    std::string goal = "Demonstrate autonomous compile error repair";
    
    if (argc > 1) {
        goal = argv[1];
    }
    
    // Create orchestrator with evidence base path
    RepairOrchestrator orchestrator("validation/val-016-2");
    
    // Execute the complete repair loop
    bool success = orchestrator.executeRepairLoop(goal);
    
    // Print final state
    std::cout << "\nFinal State: " << repairStateToString(orchestrator.getState()) << "\n";
    
    return success ? 0 : 1;
}
