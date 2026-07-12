//==============================================================================
// SovereignCLI.hpp
// CLI interface and command definitions
//==============================================================================

#ifndef SOVEREIGN_CLI_HPP
#define SOVEREIGN_CLI_HPP

#include <string>
#include <vector>

namespace sovereign {
namespace cli {

// Command result codes
enum class CommandResult {
    Success = 0,
    Error = 1,
    InvalidArgs = 2,
    NotImplemented = 3
};

// CLI configuration
struct CLIConfig {
    bool verbose = false;
    bool useMASM = true;
    bool useIntrinsics = true;
    bool useReference = false;
    int numThreads = 0;  // 0 = auto-detect
};

// Command interface
class ICommand {
public:
    virtual ~ICommand() = default;
    virtual const char* getName() const = 0;
    virtual const char* getDescription() const = 0;
    virtual CommandResult execute(int argc, char* argv[]) = 0;
};

// Command registry
class CommandRegistry {
public:
    static CommandRegistry& getInstance();
    
    void registerCommand(std::unique_ptr<ICommand> cmd);
    ICommand* findCommand(const char* name);
    void listCommands();
    
private:
    CommandRegistry() = default;
    std::vector<std::unique_ptr<ICommand>> commands;
};

// Built-in commands
class StatusCommand : public ICommand {
public:
    const char* getName() const override { return "status"; }
    const char* getDescription() const override { return "Show system status"; }
    CommandResult execute(int argc, char* argv[]) override;
};

class TestCommand : public ICommand {
public:
    const char* getName() const override { return "test"; }
    const char* getDescription() const override { return "Run validation tests"; }
    CommandResult execute(int argc, char* argv[]) override;
};

class BenchmarkCommand : public ICommand {
public:
    const char* getName() const override { return "benchmark"; }
    const char* getDescription() const override { return "Run performance benchmarks"; }
    CommandResult execute(int argc, char* argv[]) override;
};

class MemoryCommand : public ICommand {
public:
    const char* getName() const override { return "memory"; }
    const char* getDescription() const override { return "Show memory bridge status"; }
    CommandResult execute(int argc, char* argv[]) override;
};

} // namespace cli
} // namespace sovereign

#endif // SOVEREIGN_CLI_HPP
