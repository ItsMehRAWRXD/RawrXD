// Production command bridge for Win32IDE extensions.
// This registry is an explicit local command surface, not a VS Code/QuickJS host.
// Only registered callbacks execute; arbitrary command names fail closed.
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
    }

    bool RegisterCommand(const std::string& command, CommandHandler handler) {
        if (command.empty() || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
        return commands_.emplace(command, std::move(handler)).second;
    }

    bool UnregisterCommand(const std::string& command) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
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
};

} // namespace Extensions
} // namespace RawrXD

extern "C" void Bridge_OnSuggestionReady(const char* suggestion, int length) {
    // No consumer callback is wired. Never claim suggestion delivery.
    (void)suggestion;
    (void)length;
}
