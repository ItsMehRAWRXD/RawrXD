// HTTP Client Implementation
// Copyright (c) 2026 RawrXD Team

#include "http_client.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>

namespace rawrxd::benchmark {

// ============================================================================
// Connection Pool Implementation
// ============================================================================

ConnectionPool::ConnectionPool(size_t max_connections, 
                               int connection_timeout_ms,
                               int idle_timeout_ms)
    : max_connections_(max_connections),
      connection_timeout_ms_(connection_timeout_ms),
      idle_timeout_ms_(idle_timeout_ms) {}

ConnectionPool::~ConnectionPool() {
    CloseAll();
}

std::shared_ptr<ConnectionPool::Connection> ConnectionPool::Acquire(
    const std::string& host, int port) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Look for existing idle connection
    for (auto& conn : connections_) {
        if (!conn->in_use && conn->host == host && conn->port == port) {
            // Check if connection is still alive
            // (simplified - in production, send a ping)
            conn->in_use = true;
            conn->last_used = Clock::now();
            return conn;
        }
    }
    
    // Create new connection if under limit
    if (connections_.size() < max_connections_) {
        auto conn = CreateConnection(host, port);
        if (conn) {
            conn->in_use = true;
            connections_.push_back(conn);
            return conn;
        }
    }
    
    // Wait for connection to become available
    // (simplified - in production, use condition variable)
    return nullptr;
}

void ConnectionPool::Release(std::shared_ptr<Connection> conn) {
    if (!conn) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    conn->in_use = false;
    conn->last_used = Clock::now();
    conn->use_count++;
}

void ConnectionPool::CloseAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& conn : connections_) {
        if (conn->socket_fd >= 0) {
            #ifdef _WIN32
                closesocket(conn->socket_fd);
            #else
                close(conn->socket_fd);
            #endif
        }
    }
    connections_.clear();
}

ConnectionPool::Stats ConnectionPool::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats;
    stats.total_connections = connections_.size();
    
    for (const auto& conn : connections_) {
        if (conn->in_use) {
            stats.active_connections++;
        } else {
            stats.idle_connections++;
        }
    }
    
    return stats;
}

std::shared_ptr<ConnectionPool::Connection> ConnectionPool::CreateConnection(
    const std::string& host, int port) {
    
    auto conn = std::make_shared<Connection>();
    conn->host = host;
    conn->port = port;
    
    // Create socket
    #ifdef _WIN32
        conn->socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    #else
        conn->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif
    
    if (conn->socket_fd < 0) {
        return nullptr;
    }
    
    // Set non-blocking
    #ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(conn->socket_fd, FIONBIO, &mode);
    #else
        int flags = fcntl(conn->socket_fd, F_GETFL, 0);
        fcntl(conn->socket_fd, F_SETFL, flags | O_NONBLOCK);
    #endif
    
    // Resolve host
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) {
        closesocket(conn->socket_fd);
        return nullptr;
    }
    
    // Connect
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (connect(conn->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        #ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(conn->socket_fd);
                return nullptr;
            }
        #else
            if (errno != EINPROGRESS) {
                close(conn->socket_fd);
                return nullptr;
            }
        #endif
    }
    
    return conn;
}

void ConnectionPool::CleanupIdleConnections() {
    auto now = Clock::now();
    
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [&now, this](const auto& conn) {
                if (!conn->in_use) {
                    auto idle_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - conn->last_used).count();
                    if (idle_time > idle_timeout_ms_) {
                        if (conn->socket_fd >= 0) {
                            #ifdef _WIN32
                                closesocket(conn->socket_fd);
                            #else
                                close(conn->socket_fd);
                            #endif
                        }
                        return true;
                    }
                }
                return false;
            }),
        connections_.end()
    );
}

// ============================================================================
// HTTP Client Implementation
// ============================================================================

HttpClient::HttpClient() {}

HttpClient::~HttpClient() {
    Shutdown();
}

bool HttpClient::Initialize() {
    if (initialized_) return true;
    
    #ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data_) != 0) {
            return false;
        }
    #endif
    
    initialized_ = true;
    return true;
}

void HttpClient::Shutdown() {
    if (!initialized_) return;
    
    if (connection_pool_) {
        connection_pool_>CloseAll();
        connection_pool_.reset();
    }
    
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    initialized_ = false;
}

HttpResponse HttpClient::Request(const HttpRequest& request) {
    if (!initialized_) {
        HttpResponse response;
        response.error_message = "HTTP client not initialized";
        return response;
    }
    
    return ExecuteWithRetry(request);
}

HttpResponse HttpClient::Get(const std::string& url, 
                             const std::map<std::string, std::string>& headers) {
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.headers = headers;
    return Request(request);
}

HttpResponse HttpClient::Post(const std::string& url,
                              const std::string& body,
                              const std::map<std::string, std::string>& headers) {
    HttpRequest request;
    request.method = "POST";
    request.url = url;
    request.body = body;
    request.headers = headers;
    request.headers["Content-Length"] = std::to_string(body.length());
    return Request(request);
}

HttpResponse HttpClient::PostJson(const std::string& url,
                                  const std::string& json_body,
                                  const std::map<std::string, std::string>& headers) {
    HttpRequest request;
    request.method = "POST";
    request.url = url;
    request.SetJsonBody(json_body);
    request.headers = headers;
    return Request(request);
}

void HttpClient::SetDefaultTimeout(int connect_ms, int read_ms, int total_ms) {
    default_connect_timeout_ms_ = connect_ms;
    default_read_timeout_ms_ = read_ms;
    default_total_timeout_ms_ = total_ms;
}

void HttpClient::SetRetryPolicy(int max_retries, int delay_ms, bool exponential) {
    default_max_retries_ = max_retries;
    default_retry_delay_ms_ = delay_ms;
    default_exponential_backoff_ = exponential;
}

void HttpClient::SetUserAgent(const std::string& user_agent) {
    user_agent_ = user_agent;
}

void HttpClient::EnableConnectionPool(size_t max_connections) {
    if (!connection_pool_) {
        connection_pool_ = std::make_unique<ConnectionPool>(max_connections);
    }
    use_connection_pool_ = true;
}

void HttpClient::DisableConnectionPool() {
    use_connection_pool_ = false;
    if (connection_pool_) {
        connection_pool_>CloseAll();
        connection_pool_.reset();
    }
}

HttpClient::Stats HttpClient::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void HttpClient::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = Stats{};
}

HttpResponse HttpClient::ExecuteWithRetry(const HttpRequest& request) {
    RetryPolicy retry_policy(default_max_retries_, default_retry_delay_ms_, 
                            default_exponential_backoff_);
    
    HttpResponse last_response;
    
    for (int attempt = 0; attempt <= default_max_retries_; ++attempt) {
        last_response = ExecuteRequest(request);
        
        if (last_response.IsSuccess()) {
            UpdateStats(last_response);
            return last_response;
        }
        
        if (!retry_policy.ShouldRetry(attempt, last_response)) {
            break;
        }
        
        // Increment retry counter
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.retried_requests++;
        }
        
        // Wait before retry
        if (attempt < default_max_retries_) {
            int delay = retry_policy.GetDelayMs(attempt);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
    }
    
    UpdateStats(last_response);
    return last_response;
}

HttpResponse HttpClient::ExecuteRequest(const HttpRequest& request) {
    HttpResponse response;
    
    // Parse URL
    std::string host, path;
    int port;
    bool use_https;
    
    if (!ParseUrl(request.url, host, port, path, use_https)) {
        response.error_message = "Failed to parse URL: " + request.url;
        return response;
    }
    
    // Get connection
    std::shared_ptr<ConnectionPool::Connection> conn;
    if (use_connection_pool_ && connection_pool_) {
        conn = connection_pool_>Acquire(host, port);
    }
    
    // Create new connection if needed
    int socket_fd = -1;
    if (conn) {
        socket_fd = conn->socket_fd;
    } else {
        // Create new socket
        #ifdef _WIN32
            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        #else
            socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        #endif
        
        if (socket_fd < 0) {
            response.error_message = "Failed to create socket";
            return response;
        }
        
        // Set timeouts
        TimeoutManager timeout_mgr(request.connect_timeout_ms, 
                                   request.read_timeout_ms,
                                   request.total_timeout_ms);
        timeout_mgr.SetSocketTimeouts(socket_fd);
        
        // Resolve and connect
        struct hostent* server = gethostbyname(host.c_str());
        if (!server) {
            response.error_message = "Failed to resolve host: " + host;
            #ifdef _WIN32
                closesocket(socket_fd);
            #else
                close(socket_fd);
            #endif
            return response;
        }
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        
        auto start = Clock::now();
        
        if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            response.error_message = "Failed to connect to " + host + ":" + std::to_string(port);
            #ifdef _WIN32
                closesocket(socket_fd);
            #else
                close(socket_fd);
            #endif
            return response;
        }
        
        // Build and send request
        std::string request_str = BuildRequestString(request, host, path);
        
        if (send(socket_fd, request_str.c_str(), request_str.length(), 0) < 0) {
            response.error_message = "Failed to send request";
            #ifdef _WIN32
                closesocket(socket_fd);
            #else
                close(socket_fd);
            #endif
            return response;
        }
        
        // Receive response
        std::string response_data;
        char buffer[4096];
        int bytes_received;
        
        while ((bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';
            response_data += buffer;
        }
        
        auto end = Clock::now();
        response.latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        // Close socket
        #ifdef _WIN32
            closesocket(socket_fd);
        #else
            close(socket_fd);
        #endif
        
        // Parse response
        response = ParseResponse(response_data);
    }
    
    // Release connection back to pool
    if (conn && connection_pool_) {
        connection_pool_>Release(conn);
    }
    
    return response;
}

bool HttpClient::ParseUrl(const std::string& url, std::string& host, int& port, 
                          std::string& path, bool& use_https) {
    use_https = false;
    port = 80;
    
    std::string temp = url;
    
    // Check for protocol
    if (temp.substr(0, 8) == "https://") {
        use_https = true;
        port = 443;
        temp = temp.substr(8);
    } else if (temp.substr(0, 7) == "http://") {
        temp = temp.substr(7);
    }
    
    // Find path
    size_t path_pos = temp.find('/');
    if (path_pos != std::string::npos) {
        path = temp.substr(path_pos);
        temp = temp.substr(0, path_pos);
    } else {
        path = "/";
    }
    
    // Find port
    size_t port_pos = temp.find(':');
    if (port_pos != std::string::npos) {
        host = temp.substr(0, port_pos);
        try {
            port = std::stoi(temp.substr(port_pos + 1));
        } catch (...) {
            return false;
        }
    } else {
        host = temp;
    }
    
    return !host.empty();
}

std::string HttpClient::BuildRequestString(const HttpRequest& request, 
                                           const std::string& host, 
                                           const std::string& path) {
    std::ostringstream oss;
    
    oss << request.method << " " << path << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << user_agent_ << "\r\n";
    oss << "Accept: */*\r\n";
    oss << "Connection: keep-alive\r\n";
    
    for (const auto& [name, value] : request.headers) {
        oss << name << ": " << value << "\r\n";
    }
    
    oss << "\r\n";
    
    if (!request.body.empty()) {
        oss << request.body;
    }
    
    return oss.str();
}

HttpResponse HttpClient::ParseResponse(const std::string& response_data) {
    HttpResponse response;
    response.success = false;
    
    if (response_data.empty()) {
        response.error_message = "Empty response";
        return response;
    }
    
    // Find end of headers
    size_t header_end = response_data.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        header_end = response_data.find("\n\n");
        if (header_end == std::string::npos) {
            response.error_message = "Invalid response format";
            return response;
        }
    }
    
    std::string header_section = response_data.substr(0, header_end);
    response.body = response_data.substr(header_end + 4);
    
    // Parse status line
    std::istringstream header_stream(header_section);
    std::string status_line;
    std::getline(header_stream, status_line);
    
    // Remove \r if present
    if (!status_line.empty() && status_line.back() == '\r') {
        status_line.pop_back();
    }
    
    // Parse HTTP version and status
    size_t first_space = status_line.find(' ');
    size_t second_space = status_line.find(' ', first_space + 1);
    
    if (first_space != std::string::npos && second_space != std::string::npos) {
        try {
            response.status_code = std::stoi(status_line.substr(first_space + 1, 
                second_space - first_space - 1));
        } catch (...) {
            response.error_message = "Failed to parse status code";
            return response;
        }
        response.status_text = status_line.substr(second_space + 1);
    }
    
    // Parse headers
    std::string line;
    while (std::getline(header_stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            size_t start = value.find_first_not_of(" \t");
            if (start != std::string::npos) {
                value = value.substr(start);
            }
            
            response.headers[name] = value;
        }
    }
    
    response.success = true;
    return response;
}

void HttpClient::UpdateStats(const HttpResponse& response) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_requests++;
    
    if (response.IsSuccess()) {
        stats_.successful_requests++;
    } else {
        stats_.failed_requests++;
    }
    
    // Update latency stats
    if (stats_.total_requests == 1) {
        stats_.average_latency_ms = response.latency_ms;
        stats_.min_latency_ms = response.latency_ms;
        stats_.max_latency_ms = response.latency_ms;
    } else {
        // Running average
        stats_.average_latency_ms = 
            (stats_.average_latency_ms * (stats_.total_requests - 1) + response.latency_ms) 
            / stats_.total_requests;
        stats_.min_latency_ms = std::min(stats_.min_latency_ms, response.latency_ms);
        stats_.max_latency_ms = std::max(stats_.max_latency_ms, response.latency_ms);
    }
}

// ============================================================================
// Retry Policy Implementation
// ============================================================================

RetryPolicy::RetryPolicy(int max_retries, int base_delay_ms, bool exponential,
                         double backoff_multiplier, int max_delay_ms)
    : max_retries_(max_retries),
      base_delay_ms_(base_delay_ms),
      exponential_(exponential),
      backoff_multiplier_(backoff_multiplier),
      max_delay_ms_(max_delay_ms) {}

bool RetryPolicy::ShouldRetry(int attempt_number, const HttpResponse& response) {
    if (attempt_number >= max_retries_) {
        return false;
    }
    
    return IsRetryableError(response);
}

int RetryPolicy::GetDelayMs(int attempt_number) const {
    int delay = base_delay_ms_;
    
    if (exponential_) {
        delay = static_cast<int>(base_delay_ms_ * std::pow(backoff_multiplier_, attempt_number));
    }
    
    return std::min(delay, max_delay_ms_);
}

bool RetryPolicy::IsRetryableError(const HttpResponse& response) {
    // Retry on server errors (5xx)
    if (response.IsServerError()) {
        return true;
    }
    
    // Retry on specific client errors
    if (response.status_code == 429) { // Too Many Requests
        return true;
    }
    if (response.status_code == 408) { // Request Timeout
        return true;
    }
    if (response.status_code == 409) { // Conflict
        return true;
    }
    
    // Retry on network errors
    if (!response.success) {
        return true;
    }
    
    return false;
}

bool RetryPolicy::IsRetryableException(const std::exception& e) {
    std::string what = e.what();
    
    // Retry on timeout-related errors
    if (what.find("timeout") != std::string::npos ||
        what.find("timed out") != std::string::npos) {
        return true;
    }
    
    // Retry on connection errors
    if (what.find("connection") != std::string::npos ||
        what.find("connect") != std::string::npos) {
        return true;
    }
    
    return false;
}

// ============================================================================
// Timeout Manager Implementation
// ============================================================================

TimeoutManager::TimeoutManager(int connect_ms, int read_ms, int total_ms)
    : connect_timeout_ms_(connect_ms),
      read_timeout_ms_(read_ms),
      total_timeout_ms_(total_ms) {
    Reset();
}

bool TimeoutManager::SetSocketTimeouts(int socket_fd) {
    #ifdef _WIN32
        DWORD timeout = connect_timeout_ms_;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    #else
        struct timeval tv;
        tv.tv_sec = connect_timeout_ms_ / 1000;
        tv.tv_usec = (connect_timeout_ms_ % 1000) * 1000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    #endif
    
    return true;
}

bool TimeoutManager::IsTimedOut() const {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start_time_).count();
    return elapsed > total_timeout_ms_;
}

int TimeoutManager::GetRemainingTimeMs() const {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start_time_).count();
    return std::max(0, total_timeout_ms_ - static_cast<int>(elapsed));
}

void TimeoutManager::Reset() {
    start_time_ = Clock::now();
}

// ============================================================================
// HTTP Utility Functions
// ============================================================================

namespace http {

std::string UrlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << (int)(unsigned char)c;
            escaped << std::nouppercase;
        }
    }
    
    return escaped.str();
}

std::string UrlDecode(const std::string& value) {
    std::string result;
    result.reserve(value.length());
    
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            int hex = std::stoi(value.substr(i + 1, 2), nullptr, 16);
            result += static_cast<char>(hex);
            i += 2;
        } else if (value[i] == '+') {
            result += ' ';
        } else {
            result += value[i];
        }
    }
    
    return result;
}

std::string NormalizeHeaderName(const std::string& name) {
    std::string result = name;
    bool capitalize = true;
    
    for (char& c : result) {
        if (capitalize) {
            c = std::toupper(c);
            capitalize = false;
        } else {
            c = std::tolower(c);
        }
        
        if (c == '-') {
            capitalize = true;
        }
    }
    
    return result;
}

std::map<std::string, std::string> ParseHeaders(const std::string& header_section) {
    std::map<std::string, std::string> headers;
    std::istringstream stream(header_section);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            size_t start = value.find_first_not_of(" \t");
            if (start != std::string::npos) {
                value = value.substr(start);
            }
            
            headers[NormalizeHeaderName(name)] = value;
        }
    }
    
    return headers;
}

const char* GetStatusText(int status_code) {
    switch (status_code) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "Unknown";
    }
}

bool IsInformational(int status_code) { return status_code >= 100 && status_code < 200; }
bool IsSuccess(int status_code) { return status_code >= 200 && status_code < 300; }
bool IsRedirect(int status_code) { return status_code >= 300 && status_code < 400; }
bool IsClientError(int status_code) { return status_code >= 400 && status_code < 500; }
bool IsServerError(int status_code) { return status_code >= 500 && status_code < 600; }

} // namespace http

} // namespace rawrxd::benchmark
