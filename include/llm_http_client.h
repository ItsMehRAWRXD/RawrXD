/*
 * LLM HTTP Client Stub Header
 * Stub implementation for Gold build
 */

#ifndef LLM_HTTP_CLIENT_H
#define LLM_HTTP_CLIENT_H

#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace LLM {

struct HttpRequest {
    std::string url;
    std::string method = "POST";
    std::string body;
    std::string contentType = "application/json";
};

struct HttpResponse {
    int statusCode = 200;
    std::string body;
    bool success = true;
    std::string error;
};

class HttpClient {
public:
    static HttpClient& instance();
    
    HttpResponse send(const HttpRequest& req);
    HttpResponse post(const std::string& url, const std::string& body);
    HttpResponse get(const std::string& url);
    
    void setTimeout(int seconds);
    void setHeader(const std::string& key, const std::string& value);
    
private:
    HttpClient() = default;
};

// C interface
extern "C" {
    int llm_http_init(void);
    void llm_http_shutdown(void);
    int llm_http_post(const char* url, const char* body, char* response, int max_len);
    int llm_http_get(const char* url, char* response, int max_len);
}

} // namespace LLM
} // namespace RawrXD

#endif // LLM_HTTP_CLIENT_H
