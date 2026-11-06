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
        initialized_ = true;
        return true;
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        initialized_ = false;
        commands_.clear();
        owners_.clear();
    }

    static bool ValidIdentifier(const std::string& value) {
        return !value.empty() && !std::any_of(value.begin(), value.end(),
            [](unsigned char c) { return std::isspace(c) != 0 || c < 0x20 || c == 0x7f; });
    }

    bool RegisterCommand(const std::string& command, CommandHandler handler) {
        if (!ValidIdentifier(command) || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
        return commands_.emplace(command, std::move(handler)).second;
    }

    // Explicit ownership is required for extension-contributed commands.
    // The legacy RegisterCommand API remains available for host commands.
    bool RegisterExtensionCommand(const std::string& extensionId,
                                  const std::string& command,
                                  CommandHandler handler) {
        if (!ValidIdentifier(extensionId) || !ValidIdentifier(command) || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_ || commands_.find(command) != commands_.end()) return false;
        // Insert ownership first: if allocation fails, no executable orphan
        // command can escape extension unload cleanup.
        try {
            auto owner = owners_.emplace(command, extensionId);
            if (!owner.second) return false;
            auto inserted = commands_.emplace(command, std::move(handler));
            if (!inserted.second) {
                owners_.erase(owner.first);
                return false;
            }
        } catch (...) {
            // If ownership was inserted, erase it. If insertion itself failed,
            // there is no owner record to remove.
            owners_.erase(command);
            return false;
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
        try {
            CommandHandler handler;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!initialized_) return false;
                const auto it = commands_.find(command);
                if (it == commands_.end()) return false;
                // Copy the callback under lock, then execute without the lock.
                // Copying std::function can itself throw (e.g. allocation).
                handler = it->second;
            }
            return handler(args);
        } catch (...) {
            // Callback failures and callback-copy failures both fail closed.
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
