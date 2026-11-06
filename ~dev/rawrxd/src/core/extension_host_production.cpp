// Production command bridge for Win32IDE extensions.
// This registry is an explicit local command surface, not a VS Code/QuickJS host.
// Only registered callbacks execute; arbitrary command names fail closed.
#include <atomic>
#include <functional>
#include <memory>
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
        for (auto& item : commands_) item.second->active.store(false);
        commands_.clear();
        owners_.clear();
    }

    bool RegisterCommand(const std::string& command, CommandHandler handler) {
        if (command.empty() || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return false;
        return commands_.emplace(command, std::make_shared<CommandSlot>(std::move(handler))).second;
    }

    // Explicit ownership is required for extension-contributed commands.
    // The legacy RegisterCommand API remains available for host commands.
    bool RegisterExtensionCommand(const std::string& extensionId,
                                  const std::string& command,
                                  CommandHandler handler) {
        if (extensionId.empty() || command.empty() || !handler) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_ || commands_.find(command) != commands_.end()) return false;
        commands_.emplace(command, std::make_shared<CommandSlot>(std::move(handler)));
        owners_[command] = extensionId;
        return true;
    }

    void UnregisterExtensionCommands(const std::string& extensionId) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = owners_.begin(); it != owners_.end();) {
            if (it->second == extensionId) {
                auto cmd = commands_.find(it->first);
                if (cmd != commands_.end()) { cmd->second->active.store(false); commands_.erase(cmd); }
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
        auto cmd = commands_.find(command);
        if (cmd == commands_.end()) return false;
        cmd->second->active.store(false);
        commands_.erase(cmd);
        return true;
    }

    bool ExecuteCommand(const std::string& command, const std::string& args) {
        std::shared_ptr<CommandSlot> slot;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!initialized_) return false;
            const auto it = commands_.find(command);
            if (it == commands_.end()) return false;
            // Do not hold the registry lock during user code: callbacks may
            // register/unregister commands or dispatch nested commands.
            slot = it->second;
        }
        try {
            if (!slot->active.load()) return false;
            return slot->handler(args);
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

    struct CommandSlot {
        explicit CommandSlot(CommandHandler callback) : handler(std::move(callback)) {}
        CommandHandler handler;
        std::atomic<bool> active{true};
    };
    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::map<std::string, std::shared_ptr<CommandSlot>> commands_;
    std::map<std::string, std::string> owners_; // command -> extension ID
};

} // namespace Extensions
} // namespace RawrXD

extern "C" void Bridge_OnSuggestionReady(const char* suggestion, int length) {
    // No consumer callback is wired. Never claim suggestion delivery.
    (void)suggestion;
    (void)length;
}
