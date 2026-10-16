#include "streaming_engine.h"
#include <chrono>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <iostream>
#endif

// StreamingEngine Implementation
StreamingEngine::StreamingEngine(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics,
    std::shared_ptr<ResponseParser> parser
) : m_logger(logger), m_metrics(metrics), m_parser(parser) {
    if (m_logger) {
        m_logger->info("StreamingEngine", "Initialized");
    }
}

void StreamingEngine::startStream(
    std::function<void(const ParsedCompletion&)> onCompletion,
    std::function<void(const std::string&)> onError,
    std::function<void()> onStreamEnd
) {
    std::lock_guard<std::mutex> lock(m_bufferMutex);
    
    m_onCompletion = onCompletion;
    m_onError = onError;
    m_onStreamEnd = onStreamEnd;
    
    m_streamStartTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    
    m_firstChunkTimeMs = 0;
    m_sequenceCounter = 0;
    m_totalTokensReceived = 0;
    
    if (m_logger) {
        m_logger->info("StreamingEngine", "Stream started");
    }
}

void StreamingEngine::feedChunk(const std::string& chunk) {
    if (chunk.empty()) return;

    // Record time to first chunk
    if (m_firstChunkTimeMs == 0) {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()
        ).count();
        m_firstChunkTimeMs = now - m_streamStartTimeMs;
        
        if (m_metrics) {
            m_metrics->recordHistogram("streaming_ttfc_ms", static_cast<double>(m_firstChunkTimeMs));
        }
    }

    // Wait for buffer space if needed (backpressure)
    while (getBufferDepth() >= m_maxBufferSize) {
        if (!waitForBufferSpace(100)) {
            if (m_logger) {
                m_logger->warn("StreamingEngine", "Buffer backpressure timeout");
            }
            break;
        }
    }

    // Create stream chunk
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();

    StreamChunk streamChunk;
    streamChunk.data = chunk;
    streamChunk.sequenceNumber = m_sequenceCounter++;
    streamChunk.arrivedAtMs = now - m_streamStartTimeMs;
    streamChunk.isComplete = false;

    // Add to buffer
    {
        std::lock_guard<std::mutex> lock(m_bufferMutex);
        m_chunkBuffer.push(streamChunk);
    }

    // Notify waiting threads
    m_bufferCV.notify_one();

    // Process chunk immediately
    processChunk(streamChunk);
}

void StreamingEngine::endStream() {
    {
        std::lock_guard<std::mutex> lock(m_bufferMutex);
        if (!m_chunkBuffer.empty()) {
            auto lastChunk = m_chunkBuffer.back();
            lastChunk.isComplete = true;
        }
    }

    if (m_parser) {
        auto finalCompletions = m_parser->flush();
        for (const auto& completion : finalCompletions) {
            if (m_onCompletion) {
                m_onCompletion(completion);
            }
            m_totalTokensReceived += completion.tokenCount;
        }
    }

    // Record final metrics
    auto endTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    int64_t totalStreamMs = endTime - m_streamStartTimeMs;

    if (m_metrics) {
        m_metrics->recordHistogram("streaming_total_time_ms", static_cast<double>(totalStreamMs));
        m_metrics->recordHistogram("streaming_total_tokens", static_cast<double>(m_totalTokensReceived));
        m_metrics->incrementCounter("streaming_sessions_completed", 1);
    }

    if (m_logger) {
        m_logger->info("StreamingEngine", 
            "Stream ended: " + std::to_string(totalStreamMs) + "ms, " +
            std::to_string(m_totalTokensReceived) + " tokens, " +
            std::to_string(m_sequenceCounter) + " chunks");
    }

    if (m_onStreamEnd) {
        m_onStreamEnd();
    }
}

StreamMetrics StreamingEngine::getMetrics() const {
    StreamMetrics metrics;
    metrics.timeToFirstChunkMs = m_firstChunkTimeMs;
    metrics.totalChunks = m_sequenceCounter;
    metrics.totalTokens = m_totalTokensReceived;

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    metrics.totalStreamTimeMs = now - m_streamStartTimeMs;

    if (metrics.totalStreamTimeMs > 0 && m_totalTokensReceived > 0) {
        metrics.throughputTokensPerSec = (m_totalTokensReceived * 1000.0) / metrics.totalStreamTimeMs;
    }

    return metrics;
}

bool StreamingEngine::isStreaming() const {
    return m_streamStartTimeMs > 0;
}

bool StreamingEngine::waitForBufferSpace(int timeoutMs) {
    std::unique_lock<std::mutex> lock(m_bufferMutex);
    return m_bufferCV.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [this]() { return m_chunkBuffer.size() < m_maxBufferSize; });
}

size_t StreamingEngine::getBufferDepth() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_bufferMutex));
    return m_chunkBuffer.size();
}

void StreamingEngine::reset() {
    std::lock_guard<std::mutex> lock(m_bufferMutex);
    while (!m_chunkBuffer.empty()) {
        m_chunkBuffer.pop();
    }
    m_streamStartTimeMs = 0;
    m_firstChunkTimeMs = 0;
    m_sequenceCounter = 0;
    m_totalTokensReceived = 0;
}

void StreamingEngine::processChunk(const StreamChunk& chunk) {
    if (!m_parser) return;

    // Parse chunk using response parser to detect boundaries
    auto parsed = m_parser->parseChunk(chunk.data);
    
    for (const auto& completion : parsed) {
        if (m_onCompletion) {
            m_onCompletion(completion);
        }
        m_totalTokensReceived += completion.tokenCount;
        
        if (m_metrics) {
            m_metrics->recordHistogram("streaming_chunk_tokens", static_cast<double>(completion.tokenCount));
        }
    }
}

void StreamingEngine::handleStreamError(const std::string& error) {
    if (m_logger) {
        m_logger->error("StreamingEngine", "Stream error: " + error);
    }

    if (m_onError) {
        m_onError(error);
    }

    if (m_metrics) {
        m_metrics->incrementCounter("streaming_errors", 1);
    }
}

// HTTPStreamingClient Implementation
HTTPStreamingClient::HTTPStreamingClient(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics,
    std::shared_ptr<StreamingEngine> streamingEngine
) : m_logger(logger), m_metrics(metrics), m_streamingEngine(streamingEngine) {
    if (m_logger) {
        m_logger->info("HTTPStreamingClient", "Initialized");
    }
}

bool HTTPStreamingClient::openStream(
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& body
) {
    if (m_logger) {
        m_logger->info("HTTPStreamingClient", "Opening stream to: " + url);
    }

    if (!setupConnection(url)) {
        m_lastError = "Failed to setup connection";
        return false;
    }

    m_isConnected = true;

    // Start reading chunks in background thread
    std::thread([this]() {
        try {
            if (!readChunkedResponse()) {
                m_streamingEngine->endStream();
            }
        } catch (const std::exception& e) {
            m_streamingEngine->handleStreamError(std::string("Read exception: ") + e.what());
            m_streamingEngine->endStream();
        }
        m_isConnected = false;
    }).detach();

    return true;
}

void HTTPStreamingClient::closeStream() {
    if (m_logger) {
        m_logger->info("HTTPStreamingClient", "Closing stream");
    }
    m_isConnected = false;
#ifdef _WIN32
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    WSACleanup();
#endif
}

void HTTPStreamingClient::setConnectionTimeout(int timeoutMs) {
    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Set timeout to " + std::to_string(timeoutMs) + "ms");
    }
}
bool HTTPStreamingClient::setupConnection(const std::string& url)
{
#ifdef _WIN32
    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Setting up socket connection to: " + url);
    }

    // Parse URL: http://host:port/path or https://host:port/path
    std::string scheme, host, path;
    int port = 80;

    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos) {
        scheme = url.substr(0, schemeEnd);
        size_t restStart = schemeEnd + 3;
        size_t pathStart = url.find('/', restStart);
        if (pathStart != std::string::npos) {
            host = url.substr(restStart, pathStart - restStart);
            path = url.substr(pathStart);
        } else {
            host = url.substr(restStart);
            path = "/";
        }
        size_t portPos = host.find(':');
        if (portPos != std::string::npos) {
            port = std::atoi(host.substr(portPos + 1).c_str());
            host = host.substr(0, portPos);
        }
        if (scheme == "https") port = 443;
    } else {
        host = url;
        path = "/";
    }

    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Resolving host: " + host + " port: " + std::to_string(port));
    }

    // Initialize Winsock
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        m_lastError = "WSAStartup failed: " + std::to_string(wsaResult);
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    // Resolve host
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(port);
    int resolveResult = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
    if (resolveResult != 0) {
        m_lastError = "getaddrinfo failed: " + std::to_string(resolveResult);
        WSACleanup();
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    // Create socket
    m_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (m_socket == INVALID_SOCKET) {
        m_lastError = "socket failed: " + std::to_string(WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    // Set socket timeout
    int timeout = 10000; // 10 seconds
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // Connect
    int connectResult = connect(m_socket, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    if (connectResult == SOCKET_ERROR) {
        m_lastError = "connect failed: " + std::to_string(WSAGetLastError());
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        WSACleanup();
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    if (m_logger) {
        m_logger->info("HTTPStreamingClient", "Connected to " + host + ":" + std::to_string(port));
    }

    // Send HTTP POST request
    std::string request =
        "POST " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;

    int sendResult = send(m_socket, request.c_str(), (int)request.size(), 0);
    if (sendResult == SOCKET_ERROR) {
        m_lastError = "send failed: " + std::to_string(WSAGetLastError());
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        WSACleanup();
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Request sent, waiting for response");
    }

    return true;
#else
    m_lastError = "Socket streaming not supported on this platform";
    if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
    return false;
#endif
}
bool HTTPStreamingClient::readChunkedResponse()
{
#ifdef _WIN32
    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Reading chunked response from socket");
    }

    if (m_socket == INVALID_SOCKET) {
        m_lastError = "Socket not connected";
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    // Read HTTP response status line and headers
    std::string response;
    char buffer[4096];
    bool headersComplete = false;
    bool chunkedEncoding = false;

    // Read until we have complete headers (double CRLF)
    while (!headersComplete) {
        int bytes = recv(m_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            if (bytes == 0) {
                m_lastError = "Server closed connection";
            } else {
                m_lastError = "recv failed: " + std::to_string(WSAGetLastError());
            }
            if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
            return false;
        }
        buffer[bytes] = '\0';
        response.append(buffer, bytes);

        size_t headerEnd = response.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            headersComplete = true;
            // Check for chunked transfer encoding
            std::string headers = response.substr(0, headerEnd);
            if (headers.find("Transfer-Encoding: chunked") != std::string::npos ||
                headers.find("transfer-encoding: chunked") != std::string::npos) {
                chunkedEncoding = true;
            }
            // Remove headers from response body
            response = response.substr(headerEnd + 4);
        }
    }

    if (!chunkedEncoding) {
        m_lastError = "Response is not chunked transfer encoding";
        if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
        return false;
    }

    // Read and process chunks
    while (true) {
        // Read chunk size line
        std::string sizeLine;
        while (true) {
            // Look for CRLF in existing response data
            size_t crlf = response.find("\r\n");
            if (crlf != std::string::npos) {
                sizeLine = response.substr(0, crlf);
                response = response.substr(crlf + 2);
                break;
            }
            // Need more data
            int bytes = recv(m_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                m_lastError = "Connection closed while reading chunk size";
                if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
                return false;
            }
            buffer[bytes] = '\0';
            response.append(buffer, bytes);
        }

        // Parse chunk size (hex)
        size_t chunkSize = 0;
        try {
            chunkSize = std::stoul(sizeLine, nullptr, 16);
        } catch (...) {
            m_lastError = "Invalid chunk size: " + sizeLine;
            if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
            return false;
        }

        if (chunkSize == 0) {
            // Terminal chunk - read trailing CRLF and end
            if (m_logger) m_logger->debug("HTTPStreamingClient", "Received terminal chunk");
            break;
        }

        // Read chunk data
        while (response.size() < chunkSize) {
            int bytes = recv(m_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                m_lastError = "Connection closed while reading chunk data";
                if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
                return false;
            }
            buffer[bytes] = '\0';
            response.append(buffer, bytes);
        }

        std::string chunkData = response.substr(0, chunkSize);
        response = response.substr(chunkSize);

        // Read trailing CRLF after chunk data
        while (response.size() < 2) {
            int bytes = recv(m_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                m_lastError = "Connection closed after chunk data";
                if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
                return false;
            }
            buffer[bytes] = '\0';
            response.append(buffer, bytes);
        }
        response = response.substr(2); // Skip CRLF

        // Feed chunk to streaming engine
        m_streamingEngine->feedChunk(chunkData);
    }

    // Read trailing headers after terminal chunk (optional)
    // Consume remaining data until connection closes or we have enough
    if (m_logger) {
        m_logger->debug("HTTPStreamingClient", "Chunked response complete");
    }

    return true;
#else
    m_lastError = "Socket streaming not supported on this platform";
    if (m_logger) m_logger->error("HTTPStreamingClient", m_lastError);
    return false;
#endif
}

std::string HTTPStreamingClient::parseChunkSize(const std::string& line) {
    // Parse chunk size from chunked transfer encoding
    // Format: [size in hex] CRLF
    size_t pos = line.find(';');
    if (pos != std::string::npos) {
        return line.substr(0, pos);
    }
    return line;
}

// StreamingResponseBuilder Implementation
StreamingResponseBuilder::StreamingResponseBuilder() {
    m_startTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

void StreamingResponseBuilder::addCompletion(const ParsedCompletion& completion) {
    m_accumulator += completion.text;
    m_completions.push_back(completion);
    m_totalTokens += completion.tokenCount;
}

std::vector<ParsedCompletion> StreamingResponseBuilder::getCompletions() const {
    return m_completions;
}

std::string StreamingResponseBuilder::getFullText() const {
    return m_accumulator;
}

int64_t StreamingResponseBuilder::getElapsedMs() const {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    return now - m_startTimeMs;
}

void StreamingResponseBuilder::reset() {
    m_accumulator.clear();
    m_completions.clear();
    m_totalTokens = 0;
    m_startTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}
