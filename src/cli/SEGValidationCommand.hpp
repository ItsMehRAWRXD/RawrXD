#pragma once

/**
 * SEGValidationCommand.hpp
 * 
 * CLI command for SEG validation
 * Usage: rawrxd seg-validate [--json]
 */

#include "SovereignCLI.hpp"

namespace sovereign {
namespace cli {

class SEGValidationCommand : public ICommand {
public:
    const char* getName() const override { return "seg-validate"; }
    const char* getDescription() const override {
        return "Validate Sovereign Execution Graph end-to-end";
    }
    CommandResult execute(int argc, char* argv[]) override;
};

} // namespace cli
} // namespace sovereign
