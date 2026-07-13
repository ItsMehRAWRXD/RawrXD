// security_middleware.cpp
// Batch 13: Security Middleware
//
// Centralized security layer for request processing
// Features: CORS, CSP, security headers, request filtering

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <regex>
#include <optional>

namespace Benchmark {
namespace Security {

// Security headers configuration
struct SecurityHeaders {
    // Content Security Policy
    std::string content_security_policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:;";
    
    // Strict Transport Security
    std::string strict_transport_security = "max-age=31536000; includeSubDomains";
    
    // X-Frame-Options
    std::string x_frame_options = "DENY";
    
    // X-Content-Type-Options
    std::string x_content_type_options = "nosniff";
    
    // X-XSS-Protection
    std::string x_xss_protection = "1; mode=block";
    
    // Referrer-Policy
    std::string referrer_policy = "strict-origin-when-cross-origin";
    
    // Permissions-Policy
    std::string permissions_policy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
    
    std::map<std::string, std::string> ToMap() const {
        return {
            {"Content-Security-Policy", content_security_policy},
            {"Strict-Transport-Security", strict_transport_security},
            {"X-Frame-Options", x_frame_options},
            {"X-Content-Type-Options", x_content_type_options},
            {"X-XSS-Protection", x_xss_protection},
            {"Referrer-Policy", referrer_policy},
            {"Permissions-Policy", permissions_policy}
        };
    }
};

// CORS configuration
struct CORSConfig {
    std::vector<std::string> allowed_origins = {"*"};
    std::vector<std::string> allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
    std::vector<std::string> allowed_headers = {"Content-Type", "Authorization", "X-API-Key"};
    std::vector<std::string> exposed_headers = {"X-RateLimit-Limit", "X-RateLimit-Remaining"};
    bool allow_credentials = false;
    int max_age = 86400;
    
    bool IsOriginAllowed(const std::string& origin) const {
        if (allowed_origins.empty() || 
            (allowed_origins.size() == 1 && allowed_origins[0] == "*")) {
            return true;
        }
        
        for (const auto& allowed : allowed_origins) {
            if (origin == allowed) {
                return true;
            }
        }
        
        return false;
    }
};

// Request context
struct RequestContext {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string client_ip;
    std::string user_agent;
    std::string origin;
    int64_t timestamp;
};

// Response context
struct ResponseContext {
    int status_code = 200;
    std::map<std::string, std::string> headers;
    std::string body;
    bool blocked = false;
    std::string block_reason;
};

// Security middleware
class SecurityMiddleware {
public:
    struct Config {
        SecurityHeaders security_headers;
        CORSConfig cors_config;
        bool enable_ip_filtering = true;
        bool enable_request_size_limit = true;
        size_t max_request_size = 10 * 1024 * 1024;  // 10MB
        std::vector<std::string> blocked_ips;
        std::vector<std::string> blocked_user_agents;
        std::vector<std::string> blocked_paths;
    };
    
    explicit SecurityMiddleware(const Config& config = Config()) 
        : config_(config) {}
    
    // Process incoming request
    ResponseContext ProcessRequest(const RequestContext& request) {
        ResponseContext response;
        
        // Apply security checks
        if (!CheckIPFilter(request.client_ip)) {
            response.blocked = true;
            response.block_reason = "IP blocked";
            response.status_code = 403;
            return response;
        }
        
        if (!CheckUserAgent(request.user_agent)) {
            response.blocked = true;
            response.block_reason = "User-Agent blocked";
            response.status_code = 403;
            return response;
        }
        
        if (!CheckPath(request.path)) {
            response.blocked = true;
            response.block_reason = "Path blocked";
            response.status_code = 403;
            return response;
        }
        
        if (!CheckRequestSize(request.body.size())) {
            response.blocked = true;
            response.block_reason = "Request too large";
            response.status_code = 413;
            return response;
        }
        
        // Handle CORS preflight
        if (request.method == "OPTIONS") {
            return HandleCORSPrelight(request);
        }
        
        // Add CORS headers
        AddCORSHeaders(response, request.origin);
        
        // Add security headers
        AddSecurityHeaders(response);
        
        return response;
    }
    
    // Process outgoing response
    void ProcessResponse(ResponseContext& response, const RequestContext& request) {
        // Add security headers if not already present
        AddSecurityHeaders(response);
        
        // Add CORS headers
        AddCORSHeaders(response, request.origin);
        
        // Remove sensitive headers
        RemoveSensitiveHeaders(response);
    }
    
    // Check if request should be blocked
    bool ShouldBlock(const RequestContext& request, std::string& reason) {
        if (!CheckIPFilter(request.client_ip)) {
            reason = "IP blocked";
            return true;
        }
        
        if (!CheckUserAgent(request.user_agent)) {
            reason = "User-Agent blocked";
            return true;
        }
        
        if (!CheckPath(request.path)) {
            reason = "Path blocked";
            return true;
        }
        
        if (!CheckRequestSize(request.body.size())) {
            reason = "Request too large";
            return true;
        }
        
        return false;
    }

private:
    Config config_;
    
    bool CheckIPFilter(const std::string& ip) const {
        if (!config_.enable_ip_filtering || config_.blocked_ips.empty()) {
            return true;
        }
        
        for (const auto& blocked : config_.blocked_ips) {
            if (ip == blocked) {
                return false;
            }
            
            // Check CIDR notation (simplified)
            if (blocked.find('/') != std::string::npos) {
                // In production: Implement proper CIDR matching
            }
        }
        
        return true;
    }
    
    bool CheckUserAgent(const std::string& user_agent) const {
        if (config_.blocked_user_agents.empty()) {
            return true;
        }
        
        std::string lower_ua = user_agent;
        std::transform(lower_ua.begin(), lower_ua.end(), lower_ua.begin(), ::tolower);
        
        for (const auto& blocked : config_.blocked_user_agents) {
            if (lower_ua.find(blocked) != std::string::npos) {
                return false;
            }
        }
        
        return true;
    }
    
    bool CheckPath(const std::string& path) const {
        if (config_.blocked_paths.empty()) {
            return true;
        }
        
        for (const auto& blocked : config_.blocked_paths) {
            if (path.find(blocked) != std::string::npos) {
                return false;
            }
        }
        
        // Check for path traversal
        if (path.find("..") != std::string::npos) {
            return false;
        }
        
        return true;
    }
    
    bool CheckRequestSize(size_t size) const {
        if (!config_.enable_request_size_limit) {
            return true;
        }
        
        return size <= config_.max_request_size;
    }
    
    ResponseContext HandleCORSPrelight(const RequestContext& request) {
        ResponseContext response;
        response.status_code = 204;  // No Content
        
        // Add CORS headers
        AddCORSHeaders(response, request.origin);
        
        // Add allowed methods
        std::string methods;
        for (size_t i = 0; i < config_.cors_config.allowed_methods.size(); ++i) {
            if (i > 0) methods += ", ";
            methods += config_.cors_config.allowed_methods[i];
        }
        response.headers["Access-Control-Allow-Methods"] = methods;
        
        // Add allowed headers
        std::string headers;
        for (size_t i = 0; i < config_.cors_config.allowed_headers.size(); ++i) {
            if (i > 0) headers += ", ";
            headers += config_.cors_config.allowed_headers[i];
        }
        response.headers["Access-Control-Allow-Headers"] = headers;
        
        // Add max age
        response.headers["Access-Control-Max-Age"] = 
            std::to_string(config_.cors_config.max_age);
        
        return response;
    }
    
    void AddCORSHeaders(ResponseContext& response, const std::string& origin) {
        if (origin.empty()) {
            return;
        }
        
        if (config_.cors_config.IsOriginAllowed(origin)) {
            response.headers["Access-Control-Allow-Origin"] = origin;
        }
        
        if (config_.cors_config.allow_credentials) {
            response.headers["Access-Control-Allow-Credentials"] = "true";
        }
        
        // Add exposed headers
        if (!config_.cors_config.exposed_headers.empty()) {
            std::string headers;
            for (size_t i = 0; i < config_.cors_config.exposed_headers.size(); ++i) {
                if (i > 0) headers += ", ";
                headers += config_.cors_config.exposed_headers[i];
            }
            response.headers["Access-Control-Expose-Headers"] = headers;
        }
    }
    
    void AddSecurityHeaders(ResponseContext& response) {
        auto headers = config_.security_headers.ToMap();
        
        for (const auto& [key, value] : headers) {
            // Only add if not already present
            if (response.headers.find(key) == response.headers.end()) {
                response.headers[key] = value;
            }
        }
    }
    
    void RemoveSensitiveHeaders(ResponseContext& response) {
        std::vector<std::string> sensitive = {
            "X-Powered-By",
            "Server",
            "X-AspNet-Version"
        };
        
        for (const auto& header : sensitive) {
            response.headers.erase(header);
        }
    }
};

// Request sanitizer
class RequestSanitizer {
public:
    // Sanitize request body
    static std::string SanitizeBody(const std::string& body) {
        std::string result = body;
        
        // Remove null bytes
        result.erase(
            std::remove(result.begin(), result.end(), '\0'),
            result.end()
        );
        
        // Limit line length
        std::stringstream input(result);
        std::stringstream output;
        std::string line;
        
        while (std::getline(input, line)) {
            if (line.length() > 10000) {
                line = line.substr(0, 10000);
            }
            output << line << "\n";
        }
        
        return output.str();
    }
    
    // Sanitize header value
    static std::string SanitizeHeader(const std::string& value) {
        std::string result;
        
        for (char c : value) {
            // Only allow printable ASCII
            if (c >= 32 && c < 127) {
                result += c;
            }
        }
        
        // Limit length
        if (result.length() > 8192) {
            result = result.substr(0, 8192);
        }
        
        return result;
    }
    
    // Sanitize URL path
    static std::string SanitizePath(const std::string& path) {
        std::string result;
        
        // Remove null bytes
        for (char c : path) {
            if (c != '\0') {
                result += c;
            }
        }
        
        // Normalize path
        std::vector<std::string> components;
        std::stringstream ss(result);
        std::string component;
        
        while (std::getline(ss, component, '/')) {
            if (component == "..") {
                if (!components.empty()) {
                    components.pop_back();
                }
            } else if (!component.empty() && component != ".") {
                components.push_back(component);
            }
        }
        
        // Rebuild path
        result.clear();
        for (const auto& comp : components) {
            result += "/" + comp;
        }
        
        if (result.empty()) {
            result = "/";
        }
        
        return result;
    }
};

// Security policy enforcer
class SecurityPolicyEnforcer {
public:
    struct Policy {
        bool require_https = true;
        bool require_auth = true;
        int max_session_duration = 3600;
        int max_idle_time = 900;
        std::vector<std::string> allowed_hosts;
        std::map<std::string, std::vector<std::string>> method_restrictions;
    };
    
    explicit SecurityPolicyEnforcer(const Policy& policy = Policy()) 
        : policy_(policy) {}
    
    bool EnforceHTTPS(const RequestContext& request, ResponseContext& response) {
        if (!policy_.require_https) {
            return true;
        }
        
        auto it = request.headers.find("X-Forwarded-Proto");
        if (it != request.headers.end() && it->second == "https") {
            return true;
        }
        
        // Check if request is HTTPS
        // In production: Check request scheme
        
        response.status_code = 403;
        response.body = "HTTPS required";
        return false;
    }
    
    bool EnforceHost(const RequestContext& request, ResponseContext& response) {
        if (policy_.allowed_hosts.empty()) {
            return true;
        }
        
        auto it = request.headers.find("Host");
        if (it == request.headers.end()) {
            response.status_code = 400;
            return false;
        }
        
        for (const auto& allowed : policy_.allowed_hosts) {
            if (it->second == allowed) {
                return true;
            }
        }
        
        response.status_code = 403;
        response.body = "Invalid Host header";
        return false;
    }
    
    bool EnforceMethod(const std::string& path, const std::string& method,
                       ResponseContext& response) {
        auto it = policy_.method_restrictions.find(path);
        if (it == policy_.method_restrictions.end()) {
            return true;
        }
        
        for (const auto& allowed : it->second) {
            if (method == allowed) {
                return true;
            }
        }
        
        response.status_code = 405;
        response.headers["Allow"] = "GET, POST";  // List allowed methods
        return false;
    }

private:
    Policy policy_;
};

} // namespace Security
} // namespace Benchmark
