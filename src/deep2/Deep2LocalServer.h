#pragma once

#include "Deep2InferenceGateway.h"
#include <string>
#include <thread>
#include <atomic>

namespace Deep2 {

// OpenAI-compatible local server for sovereign AI inference
// Runs on localhost only - no external network
class Deep2LocalServer {
public:
    Deep2LocalServer();
    ~Deep2LocalServer();

    // Initialize with model and port
    bool Initialize(
        const std::string& modelPath,
        int port = 11442,
        const std::string& host = "127.0.0.1"
    );

    // Start server (blocking)
    void Run();

    // Start server (non-blocking)
    bool RunAsync();

    // Stop server
    void Stop();

    // Check if running
    bool IsRunning() const { return running_.load(); }

    // Get server info
    std::string GetEndpoint() const { return endpoint_; }
    std::string GetModelInfo() const;

private:
    Deep2InferenceGateway gateway_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread serverThread_;
    int port_ = 11442;
    std::string host_ = "127.0.0.1";
    std::string endpoint_;

    // HTTP server implementation
    void ServerLoop();
    void HandleRequest(int clientSocket);
    std::string ProcessOpenAIRequest(const std::string& jsonRequest);
};

} // namespace Deep2
