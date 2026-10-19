#include "api_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

using namespace Deep2Rom::Inference;

namespace Deep2Rom::Api {

    OllamaApiServer::OllamaApiServer(int port)
        : m_port(port), m_listenSocket(INVALID_SOCKET) {}

    OllamaApiServer::~OllamaApiServer() {
        stop();
    }

    bool OllamaApiServer::start() {
        WSADATA wsa;
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "[OllamaApi] WSAStartup failed\n";
            return false;
        }

        m_listenSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_listenSocket == INVALID_SOCKET) {
            std::cerr << "[OllamaApi] socket() failed\n";
            ::WSACleanup();
            return false;
        }

        // Allow address reuse
        int optval = 1;
        ::setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = ::htons(static_cast<USHORT>(m_port));

        if (::bind(m_listenSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "[OllamaApi] bind() failed on port " << m_port << "\n";
            ::closesocket(m_listenSocket);
            ::WSACleanup();
            return false;
        }

        if (::listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "[OllamaApi] listen() failed\n";
            ::closesocket(m_listenSocket);
            ::WSACleanup();
            return false;
        }

        m_running = true;
        m_serverThread = std::thread([this]() {
            while (m_running.load()) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(m_listenSocket, &fds);

                timeval tv{};
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                int result = ::select(static_cast<int>(m_listenSocket) + 1, &fds, nullptr, nullptr, &tv);
                if (result == SOCKET_ERROR || result == 0) continue;

                SOCKET client = ::accept(m_listenSocket, nullptr, nullptr);
                if (client != INVALID_SOCKET) {
                    // Set recv timeout
                    int timeout = 5000;
                    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                    std::thread([this, client]() {
                        handleClient(client);
                        ::closesocket(client);
                    }).detach();
                }
            }
        });

        std::cout << "[OllamaApi] Server listening on port " << m_port << "\n";
        return true;
    }

    void OllamaApiServer::stop() {
        m_running = false;
        if (m_listenSocket != INVALID_SOCKET) {
            ::closesocket(m_listenSocket);
            m_listenSocket = INVALID_SOCKET;
        }
        if (m_serverThread.joinable()) {
            m_serverThread.join();
        }
        ::WSACleanup();
    }

    std::string OllamaApiServer::extractPath(const std::string& request) {
        // First line: "GET /api/tags HTTP/1.1"
        size_t firstSpace = request.find(' ');
        if (firstSpace == std::string::npos) return "";
        size_t secondSpace = request.find(' ', firstSpace + 1);
        if (secondSpace == std::string::npos) return "";
        return request.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    }

    std::string OllamaApiServer::extractBody(const std::string& request) {
        size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd == std::string::npos) return "";
        return request.substr(headerEnd + 4);
    }

    std::string OllamaApiServer::extractHeaderValue(const std::string& request, const std::string& headerName) {
        std::string search = headerName + ": ";
        size_t pos = request.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        size_t end = request.find("\r\n", pos);
        if (end == std::string::npos) return "";
        return request.substr(pos, end - pos);
    }

    void OllamaApiServer::handleClient(SOCKET clientSocket) {
        // Read request
        std::string request;
        char buf[4096];
        int totalRead = 0;
        while (true) {
            int bytes = ::recv(clientSocket, buf, sizeof(buf) - 1, 0);
            if (bytes <= 0) break;
            buf[bytes] = '\0';
            request += buf;
            totalRead += bytes;
            if (request.find("\r\n\r\n") != std::string::npos) {
                // Check Content-Length
                std::string clStr = extractHeaderValue(request, "Content-Length");
                if (!clStr.empty()) {
                    size_t contentLength = std::stoul(clStr);
                    size_t headerEnd = request.find("\r\n\r\n");
                    size_t bodyStart = headerEnd + 4;
                    size_t bodySize = request.size() - bodyStart;
                    if (bodySize >= contentLength) break;
                } else {
                    break;
                }
            }
        }

        if (request.empty()) return;

        std::string path = extractPath(request);
        std::string method;
        size_t firstSpace = request.find(' ');
        if (firstSpace != std::string::npos) {
            method = request.substr(0, firstSpace);
        }

        std::string response;

        if (method == "GET" && path == "/api/tags") {
            response = handleGetTags();
        } else if (method == "POST" && path == "/api/generate") {
            std::string body = extractBody(request);
            response = handlePostGenerate(body);
        } else if (method == "POST" && path == "/api/chat") {
            std::string body = extractBody(request);
            response = handlePostChat(body);
        } else {
            // 404
            std::string body = R"({"error":"not found"})";
            sendResponse(clientSocket, 404, "application/json", body);
            return;
        }

        sendResponse(clientSocket, 200, "application/json", response);
    }

    std::string OllamaApiServer::handleGetTags() {
        std::lock_guard<std::mutex> lock(m_modelsMutex);

        std::ostringstream oss;
        oss << R"({"models":[)";
        bool first = true;
        for (const auto& [name, path] : m_models) {
            if (!first) oss << ",";
            first = false;
            oss << R"({"name":")" << escapeJson(name)
                << R"(","modified_at":"2026-01-01T00:00:00Z","size":0,"digest":"sha256:")" 
                << escapeJson(name) << R"(","details":{}})";
        }
        oss << "]}";
        return oss.str();
    }

    std::string OllamaApiServer::handlePostGenerate(const std::string& body) {
        // Minimal JSON parsing (dependency-free)
        GenerateRequest req;
        req.num_predict = 128;
        req.temperature = 0.7f;
        req.top_p = 0.9f;
        req.top_k = 50;
        req.seed = 42;

        // Parse "model": "..."
        size_t pos = body.find("\"model\"");
        if (pos != std::string::npos) {
            pos = body.find('"', pos + 8);
            if (pos != std::string::npos) {
                size_t end = body.find('"', pos + 1);
                if (end != std::string::npos) req.model = body.substr(pos + 1, end - pos - 1);
            }
        }

        // Parse "prompt": "..."
        pos = body.find("\"prompt\"");
        if (pos != std::string::npos) {
            pos = body.find('"', pos + 8);
            if (pos != std::string::npos) {
                size_t end = body.find('"', pos + 1);
                if (end != std::string::npos) req.prompt = body.substr(pos + 1, end - pos - 1);
            }
        }

        // Parse "num_predict"
        pos = body.find("\"num_predict\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.num_predict = static_cast<uint32_t>(std::stoi(body.substr(pos)));
            }
        }

        // Parse "temperature"
        pos = body.find("\"temperature\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.temperature = std::stof(body.substr(pos));
            }
        }

        // Parse "top_p"
        pos = body.find("\"top_p\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.top_p = std::stof(body.substr(pos));
            }
        }

        // Parse "top_k"
        pos = body.find("\"top_k\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.top_k = static_cast<uint32_t>(std::stoi(body.substr(pos)));
            }
        }

        // Parse "seed"
        pos = body.find("\"seed\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.seed = static_cast<uint64_t>(std::stoull(body.substr(pos)));
            }
        }

        // Generate using the inference engine
        if (!m_engine || !m_engine->isLoaded()) {
            GenerateResponse resp;
            resp.model = req.model;
            resp.created_at = "2026-01-01T00:00:00Z";
            resp.response = "Error: No model loaded";
            resp.done = true;
            return buildJsonResponse(resp);
        }

        Deep2Rom::Inference::EngineConfig cfg;
        cfg.maxGenTokens = req.num_predict;
        cfg.temperature = req.temperature;
        cfg.topP = req.top_p;
        cfg.topK = req.top_k;
        cfg.seed = req.seed;
        cfg.addBos = true;
        cfg.addEos = true;
        cfg.skipSpecialTokens = true;

        auto startTime = std::chrono::high_resolution_clock::now();
        InferenceResult result = m_engine->generate(req.prompt, cfg);
        auto endTime = std::chrono::high_resolution_clock::now();
        double totalTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

        GenerateResponse resp;
        resp.model = req.model;
        resp.created_at = "2026-01-01T00:00:00Z";
        resp.response = result.text;
        resp.done = true;
        resp.total_duration = static_cast<uint32_t>(totalTimeMs * 1000000); // nanoseconds
        resp.eval_count = result.tokensGenerated;
        resp.eval_duration = static_cast<uint32_t>(totalTimeMs * 1000000);

        return buildJsonResponse(resp);
    }

    std::string OllamaApiServer::handlePostChat(const std::string& body) {
        ChatRequest req;
        req.num_predict = 128;
        req.temperature = 0.7f;
        req.top_p = 0.9f;
        req.top_k = 50;
        req.seed = 42;

        // Parse "model"
        size_t pos = body.find("\"model\"");
        if (pos != std::string::npos) {
            pos = body.find('"', pos + 8);
            if (pos != std::string::npos) {
                size_t end = body.find('"', pos + 1);
                if (end != std::string::npos) req.model = body.substr(pos + 1, end - pos - 1);
            }
        }

        // Parse messages — extract the last user message content
        std::string userContent;
        pos = 0;
        while ((pos = body.find("\"role\":\"user\"", pos)) != std::string::npos) {
            // Find the content after this user role
            size_t contentPos = body.find("\"content\"", pos);
            if (contentPos != std::string::npos) {
                contentPos = body.find('"', contentPos + 9);
                if (contentPos != std::string::npos) {
                    size_t end = body.find('"', contentPos + 1);
                    if (end != std::string::npos) {
                        userContent = body.substr(contentPos + 1, end - contentPos - 1);
                    }
                }
            }
            pos += 12;
        }

        // Parse generation params (same as generate)
        pos = body.find("\"num_predict\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.num_predict = static_cast<uint32_t>(std::stoi(body.substr(pos)));
            }
        }

        pos = body.find("\"temperature\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.temperature = std::stof(body.substr(pos));
            }
        }

        pos = body.find("\"top_p\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.top_p = std::stof(body.substr(pos));
            }
        }

        pos = body.find("\"top_k\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.top_k = static_cast<uint32_t>(std::stoi(body.substr(pos)));
            }
        }

        pos = body.find("\"seed\"");
        if (pos != std::string::npos) {
            pos = body.find(':', pos);
            if (pos != std::string::npos) {
                pos++;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
                req.seed = static_cast<uint64_t>(std::stoull(body.substr(pos)));
            }
        }

        // Generate
        if (!m_engine || !m_engine->isLoaded()) {
            ChatResponse resp;
            resp.model = req.model;
            resp.created_at = "2026-01-01T00:00:00Z";
            resp.message.role = "assistant";
            resp.message.content = "Error: No model loaded";
            resp.done = true;
            return buildJsonResponse(resp);
        }

        Deep2Rom::Inference::EngineConfig cfg;
        cfg.maxGenTokens = req.num_predict;
        cfg.temperature = req.temperature;
        cfg.topP = req.top_p;
        cfg.topK = req.top_k;
        cfg.seed = req.seed;
        cfg.addBos = true;
        cfg.addEos = true;
        cfg.skipSpecialTokens = true;

        auto startTime = std::chrono::high_resolution_clock::now();
        InferenceResult result = m_engine->generate(userContent, cfg);
        auto endTime = std::chrono::high_resolution_clock::now();
        double totalTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

        ChatResponse resp;
        resp.model = req.model;
        resp.created_at = "2026-01-01T00:00:00Z";
        resp.message.role = "assistant";
        resp.message.content = result.text;
        resp.done = true;

        return buildJsonResponse(resp);
    }

    std::string OllamaApiServer::escapeJson(const std::string& s) {
        std::ostringstream oss;
        for (char c : s) {
            switch (c) {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        oss << c;
                    }
            }
        }
        return oss.str();
    }

    std::string OllamaApiServer::buildJsonResponse(const GenerateResponse& resp) {
        std::ostringstream oss;
        oss << "{";
        oss << R"("model":")" << escapeJson(resp.model) << R"(",)";
        oss << R"("created_at":")" << escapeJson(resp.created_at) << R"(",)";
        oss << R"("response":")" << escapeJson(resp.response) << R"(",)";
        oss << R"("done":)" << (resp.done ? "true" : "false") << ",";
        oss << R"("total_duration":)" << resp.total_duration << ",";
        oss << R"("load_duration":)" << resp.load_duration << ",";
        oss << R"("prompt_eval_count":)" << resp.prompt_eval_count << ",";
        oss << R"("prompt_eval_duration":)" << resp.prompt_eval_duration << ",";
        oss << R"("eval_count":)" << resp.eval_count << ",";
        oss << R"("eval_duration":)" << resp.eval_duration;
        oss << "}";
        return oss.str();
    }

    std::string OllamaApiServer::buildJsonResponse(const ChatResponse& resp) {
        std::ostringstream oss;
        oss << "{";
        oss << R"("model":")" << escapeJson(resp.model) << R"(",)";
        oss << R"("created_at":")" << escapeJson(resp.created_at) << R"(",)";
        oss << R"("message":{"role":")" << escapeJson(resp.message.role) << R"(","content":")" 
            << escapeJson(resp.message.content) << R"(")},)";
        oss << R"("done":)" << (resp.done ? "true" : "false");
        oss << "}";
        return oss.str();
    }

    std::string OllamaApiServer::buildJsonTagsResponse() {
        std::lock_guard<std::mutex> lock(m_modelsMutex);
        std::ostringstream oss;
        oss << R"({"models":[)";
        bool first = true;
        for (const auto& [name, path] : m_models) {
            if (!first) oss << ",";
            first = false;
            oss << R"({"name":")" << escapeJson(name)
                << R"(","modified_at":"2026-01-01T00:00:00Z","size":0,"digest":"sha256:")" 
                << escapeJson(name) << R"(","details":{}})";
        }
        oss << "]}";
        return oss.str();
    }

    void OllamaApiServer::sendResponse(SOCKET sock, int statusCode, const std::string& contentType, const std::string& body) {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << statusCode << " OK\r\n";
        oss << "Content-Type: " << contentType << "\r\n";
        oss << "Content-Length: " << body.size() << "\r\n";
        oss << "Connection: close\r\n";
        oss << "\r\n";
        oss << body;

        std::string response = oss.str();
        ::send(sock, response.c_str(), static_cast<int>(response.size()), 0);
    }

    void OllamaApiServer::registerModel(const std::string& name, const std::string& path) {
        std::lock_guard<std::mutex> lock(m_modelsMutex);
        m_models[name] = path;
    }

} // namespace Deep2Rom::Api
