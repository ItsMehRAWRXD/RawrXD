#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <future>
<<<<<<< HEAD
#include <unordered_map>
#include <nlohmann/json.hpp>
=======
#include "nlohmann/json.hpp"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

namespace RawrXD {

struct LSPConfig {
    std::string languageId;
    std::string command;
    std::vector<std::string> args;
    std::string rootPath;
};

<<<<<<< HEAD
struct Position {
    int line;
    int character;
};

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
// Abstract transport interface
class JsonRpcTransport {
public:
    virtual ~JsonRpcTransport() = default;
    virtual bool connect(const std::string& cmd, const std::vector<std::string>& args) = 0;
    virtual void send(const nlohmann::json& msg) = 0;
    virtual nlohmann::json receive() = 0;
    virtual bool isConnected() const = 0;
};

class LSPClient {
public:
    LSPClient(const LSPConfig& config);
    ~LSPClient();
    
    bool start();
    void stop();
    
    // Core LSP methods
    std::future<nlohmann::json> initialize();
    void didOpen(const std::string& uri, const std::string& text);
    void didChange(const std::string& uri, const std::string& text);
    std::future<nlohmann::json> completion(const std::string& uri, int line, int character);
    std::future<nlohmann::json> definition(const std::string& uri, int line, int character);
    
<<<<<<< HEAD
    // Incremental sync
    void sendIncrementalUpdate(const std::string& uri, int64_t version,
                                const std::string& oldContent,
                                const std::string& newContent);
    void cancelRequest(const std::string& id);
    
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
private:
    LSPConfig m_config;
    std::unique_ptr<JsonRpcTransport> m_transport;
    std::atomic<bool> m_initialized{false};
    std::atomic<int> m_requestId{0};
    std::mutex m_mutex;
<<<<<<< HEAD
    std::unordered_map<std::string, bool> m_pendingCancellations;
    
    nlohmann::json createRequest(const std::string& method, const nlohmann::json& params);
    nlohmann::json createNotification(const std::string& method, const nlohmann::json& params);
    void sendNotification(const std::string& method, const std::string& params);
    Position offsetToPosition(const std::string& text, int offset);
=======
    
    nlohmann::json createRequest(const std::string& method, const nlohmann::json& params);
    nlohmann::json createNotification(const std::string& method, const nlohmann::json& params);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

} // namespace RawrXD

#pragma once
