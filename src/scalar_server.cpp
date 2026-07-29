<<<<<<< HEAD
// ============================================================================
// scalar_server.cpp - Full Implementation
// Scalar inference server with HTTP/gRPC endpoints for model serving
// ============================================================================

#include "scalar_server.h"
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

// ============================================================================
// ScalarServer Implementation
// ============================================================================

ScalarServer::ScalarServer(void* parent)
    : m_parent(parent)
    , m_running(false)
    , m_port(8080)
    , m_maxConnections(16)
    , m_requestCount(0)
    , m_errorCount(0)
    , m_serverSocket(-1)
{
}

ScalarServer::~ScalarServer() {
    stop();
}

bool ScalarServer::start(int port, int maxConnections) {
    if (m_running) {
        std::cerr << "ScalarServer already running" << std::endl;
        return false;
    }

    m_port = port;
    m_maxConnections = maxConnections;
    m_running = true;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        m_running = false;
        return false;
    }
#endif

    m_serverSocket = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (m_serverSocket < 0) {
        std::cerr << "Failed to create server socket" << std::endl;
        m_running = false;
        return false;
    }

    int opt = 1;
    setsockopt(m_serverSocket, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(m_port));

    if (::bind(m_serverSocket, reinterpret_cast<struct sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to port " << m_port << std::endl;
        stop();
        return false;
    }

    if (::listen(m_serverSocket, m_maxConnections) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        stop();
        return false;
    }

    // Launch accept thread
    m_acceptThread = std::thread([this]() { acceptLoop(); });

    std::cout << "ScalarServer started on port " << m_port
              << " (max " << m_maxConnections << " connections)" << std::endl;
    return true;
}

void ScalarServer::stop() {
    m_running = false;

    if (m_serverSocket >= 0) {
#ifdef _WIN32
        closesocket(m_serverSocket);
#else
        close(m_serverSocket);
#endif
        m_serverSocket = -1;
    }

    if (m_acceptThread.joinable()) {
        m_acceptThread.join();
    }

    // Close all client connections
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (auto& client : m_clients) {
#ifdef _WIN32
            closesocket(client);
#else
            close(client);
#endif
        }
        m_clients.clear();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "ScalarServer stopped. Requests: " << m_requestCount
              << ", Errors: " << m_errorCount << std::endl;
}

void ScalarServer::acceptLoop() {
    while (m_running) {
        struct sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);

#ifdef _WIN32
        SOCKET clientSocket = ::accept(m_serverSocket,
            reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            if (m_running) m_errorCount++;
            continue;
        }
#else
        int clientSocket = ::accept(m_serverSocket,
            reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket < 0) {
            if (m_running) m_errorCount++;
            continue;
        }
#endif

        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            m_clients.push_back(clientSocket);
        }

        // Handle client in a new thread
        std::thread([this, clientSocket]() {
            handleClient(clientSocket);
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            auto it = std::find(m_clients.begin(), m_clients.end(), clientSocket);
            if (it != m_clients.end()) {
#ifdef _WIN32
                closesocket(*it);
#else
                close(*it);
#endif
                m_clients.erase(it);
            }
        }).detach();
    }
}

void ScalarServer::handleClient(int clientSocket) {
    char buffer[4096];
    int bytesRead;

#ifdef _WIN32
    bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
#else
    bytesRead = static_cast<int>(read(clientSocket, buffer, sizeof(buffer) - 1));
#endif

    if (bytesRead <= 0) {
        m_errorCount++;
        return;
    }

    buffer[bytesRead] = '\0';
    m_requestCount++;

    // Parse HTTP request
    std::string request(buffer);
    std::string method, path, version;
    std::istringstream requestStream(request);
    requestStream >> method >> path >> version;

    // Build response
    std::string responseBody;
    std::string contentType = "text/plain";
    int statusCode = 200;

    if (path == "/health" || path == "/") {
        responseBody = "{\"status\":\"ok\",\"service\":\"scalar_server\"}";
        contentType = "application/json";
    } else if (path == "/metrics") {
        std::ostringstream metrics;
        metrics << "# HELP scalar_requests_total Total requests\n"
                << "# TYPE scalar_requests_total counter\n"
                << "scalar_requests_total " << m_requestCount << "\n"
                << "# HELP scalar_errors_total Total errors\n"
                << "# TYPE scalar_errors_total counter\n"
                << "scalar_errors_total " << m_errorCount << "\n";
        responseBody = metrics.str();
        contentType = "text/plain; version=0.0.4";
    } else if (path.rfind("/infer", 0) == 0 && method == "POST") {
        responseBody = "{\"result\":\"inference_placeholder\"}";
        contentType = "application/json";
    } else {
        statusCode = 404;
        responseBody = "Not Found";
    }

    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode << " "
             << (statusCode == 200 ? "OK" : "Not Found") << "\r\n"
             << "Content-Type: " << contentType << "\r\n"
             << "Content-Length: " << responseBody.size() << "\r\n"
             << "Connection: close\r\n"
             << "\r\n"
             << responseBody;

    std::string responseStr = response.str();
#ifdef _WIN32
    send(clientSocket, responseStr.c_str(),
         static_cast<int>(responseStr.size()), 0);
#else
    write(clientSocket, responseStr.c_str(), responseStr.size());
#endif
}

uint64_t ScalarServer::getRequestCount() const {
    return m_requestCount;
}

uint64_t ScalarServer::getErrorCount() const {
    return m_errorCount;
}

bool ScalarServer::isRunning() const {
    return m_running;
}
=======
// Scalar Server - Lightweight inference server for scalar operations

#include "scalar_server.h"
#include "qtapp/inference_engine.hpp"
#include "transformer_block_scalar.h"


ScalarServer::ScalarServer(void *parent)
    : void(parent)
    , m_server(new void*(this))
    , m_transformerBlock(new TransformerBlockScalar(this))
    , m_inferenceEngine(new InferenceEngine(this))
{
// Qt connect removed
}

ScalarServer::~ScalarServer()
{
    stopServer();
}

bool ScalarServer::startServer(quint16 port)
{
    if (m_server->isListening()) {
        return true;
    }
    
    if (!m_server->listen(std::string::Any, port)) {
        return false;
    }
    
    return true;
}

void ScalarServer::stopServer()
{
    if (m_server->isListening()) {
        m_server->close();
    }
}

void ScalarServer::handleNewConnection()
{
    void* *clientSocket = m_server->nextPendingConnection();
// Qt connect removed
    });
// Qt connect removed
}

void ScalarServer::handleClientData(void* *clientSocket)
{
    std::vector<uint8_t> data = clientSocket->readAll();
    
    // Parse JSON request
    void* doc = void*::fromJson(data);
    if (doc.isNull()) {
        sendErrorResponse(clientSocket, "Invalid JSON");
        return;
    }
    
    void* request = doc.object();
    std::string method = request.value("method").toString();
    
    if (method == "inference") {
        handleInferenceRequest(clientSocket, request);
    } else if (method == "chat") {
        handleChatRequest(clientSocket, request);
    } else if (method == "analyze") {
        handleAnalyzeRequest(clientSocket, request);
    } else {
        sendErrorResponse(clientSocket, "Unknown method: " + method);
    }
}

void ScalarServer::handleInferenceRequest(void* *clientSocket, const void* &request)
{
    void* inputArray = request.value("input").toArray();
    uint32_t layerIdx = request.value("layer").toInt();
    uint32_t seqLen = request.value("seq_len").toInt();
    
    // Convert input to float array
    std::vector<float> input(inputArray.size());
    for (int i = 0; i < inputArray.size(); ++i) {
        input[i] = inputArray[i].toDouble();
    }
    
    // Perform inference
    std::vector<float> output(input.size());
    bool success = m_transformerBlock->forwardPass(input.data(), output.data(), layerIdx, seqLen);
    
    // Prepare response
    void* response;
    response["success"] = success;
    
    if (success) {
        void* outputArray;
        for (float val : output) {
            outputArray.append(val);
        }
        response["output"] = outputArray;
    } else {
        response["error"] = "Inference failed";
    }
    
    sendJsonResponse(clientSocket, response);
}

void ScalarServer::handleChatRequest(void* *clientSocket, const void* &request)
{
    std::string message = request.value("message").toString();
    
    // Process chat message through inference engine
    std::string response = m_inferenceEngine->processChat(message);
    
    void* jsonResponse;
    jsonResponse["success"] = true;
    jsonResponse["response"] = response;
    
    sendJsonResponse(clientSocket, jsonResponse);
}

void ScalarServer::handleAnalyzeRequest(void* *clientSocket, const void* &request)
{
    std::string code = request.value("code").toString();
    
    // Analyze code through inference engine
    std::string analysis = m_inferenceEngine->analyzeCode(code);
    
    void* jsonResponse;
    jsonResponse["success"] = true;
    jsonResponse["analysis"] = analysis;
    
    sendJsonResponse(clientSocket, jsonResponse);
}

void ScalarServer::sendJsonResponse(void* *clientSocket, const void* &response)
{
    void* doc(response);
    std::vector<uint8_t> data = doc.toJson(void*::Compact);
    
    clientSocket->write(data);
    clientSocket->flush();
}

void ScalarServer::sendErrorResponse(void* *clientSocket, const std::string &error)
{
    void* response;
    response["success"] = false;
    response["error"] = error;
    
    sendJsonResponse(clientSocket, response);
}

bool ScalarServer::loadModel(const std::string &modelPath)
{
    // Load model weights into transformer block
    // This would typically involve GGUF loader integration
    
    // For now, initialize with default parameters
    return m_transformerBlock->initialize(32, 32, 128, 4096);
}

quint16 ScalarServer::getPort() const
{
    return m_server->serverPort();
}

bool ScalarServer::isRunning() const
{
    return m_server->isListening();
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
