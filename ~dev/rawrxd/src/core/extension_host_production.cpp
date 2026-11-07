// Production command bridge for Win32IDE extensions.
// This registry is an explicit local command surface, not a VS Code/QuickJS host.
// Only registered callbacks execute; arbitrary command names fail closed.
#include <algorithm>
#include <cctype>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace RawrXD {
namespace Extensions {

class ExtensionHost {
public:
    using CommandHandler = std::function<bool(const std::string&)>;

    static ExtensionHost& GetInstance() {
        static ExtensionHost instance;
        return instance;
    }

    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return true;
        initialized_ = true;
        return true;
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        initialized_ = false;
        commands_.clear();
        owners_.clear();
    }

    static bool ValidCommandName(const std::string& command) {
        if (command.empty() || command.size() > 256) return false;
        return std::none_of(command.begin(), command.end(), [](unsigned char c) {
            return c < 0x20 || c == 0x7f; // Includes embedded NUL (C-string truncation risk).
        });
    }

    bool RegisterCommand(const std::string& command, CommandHandler handler) {
        if (!ValidCommandName(command) || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
        return commands_.emplace(command, std::move(handler)).second;
    }

    // Explicit ownership is required for extension-contributed commands.
    // The legacy RegisterCommand API remains available for host commands.
    bool RegisterExtensionCommand(const std::string& extensionId,
                                  const std::string& command,
                                  CommandHandler handler) {
        if (extensionId.empty() || extensionId.size() > 256 || !ValidCommandName(command) || !handler) return false;
        // Reject malformed ownership identifiers before entering the registry.
        // This is a command bridge, not an extension manifest validator.
        if (std::any_of(extensionId.begin(), extensionId.end(), [](unsigned char c) { return std::isspace(c) != 0 || c < 0x20 || c == 0x7f || c == '/' || c == '\\'; })) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_ || commands_.find(command) != commands_.end()) return false;
        // Install ownership first, then the callback. If callback insertion
        // throws, roll ownership back; never leave an executable orphan.
        owners_.emplace(command, extensionId);
        try {
            commands_.emplace(command, std::move(handler));
        } catch (...) {
            owners_.erase(command);
            throw;
        }
        return true;
    }

    void UnregisterExtensionCommands(const std::string& extensionId) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = owners_.begin(); it != owners_.end();) {
            if (it->second == extensionId) {
                commands_.erase(it->first);
                it = owners_.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool UnregisterCommand(const std::string& command) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
        owners_.erase(command);
        return commands_.erase(command) == 1;
    }

    bool ExecuteCommand(const std::string& command, const std::string& args) {
        CommandHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!initialized_) return false;
            const auto it = commands_.find(command);
            if (it == commands_.end()) return false;
            // Do not hold the registry lock during user code: callbacks may
            // register/unregister commands or dispatch nested commands.
            handler = it->second;
        }
        try {
            return handler(args);
        } catch (...) {
            // Command failure must not crash the IDE or report success.
            return false;
        }
    }

    std::vector<std::string> GetAvailableCommands() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        if (!initialized_) return result;
        for (const auto& command : commands_) result.push_back(command.first);
        return result;
    }

    bool IsInitialized() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return initialized_;
    }

private:
    ExtensionHost() = default;
    ~ExtensionHost() { Shutdown(); }
    ExtensionHost(const ExtensionHost&) = delete;
    ExtensionHost& operator=(const ExtensionHost&) = delete;

    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::map<std::string, CommandHandler> commands_;
    std::map<std::string, std::string> owners_; // command -> extension ID
};

} // namespace Extensions
} // namespace RawrXD

extern "C" void Bridge_OnSuggestionReady(const char* suggestion, int length) {
    // No consumer callback is wired. Never claim suggestion delivery.
    (void)suggestion;
    (void)length;
}
