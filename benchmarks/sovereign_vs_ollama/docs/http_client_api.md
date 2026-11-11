# HTTP Client API Documentation

## Overview

The RawrXD Benchmark HTTP Client is a custom-built HTTP client designed for high-performance benchmarking of LLM backends. It provides connection pooling, retry policies, timeout management, and platform-specific optimizations for Windows and Linux.

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Connection Pool](#connection-pool)
- [Request/Response](#requestresponse)
- [Retry Policies](#retry-policies)
- [Timeout Management](#timeout-management)
- [Error Handling](#error-handling)
- [Advanced Usage](#advanced-usage)
- [Platform Notes](#platform-notes)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      HttpClient                              │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Connection   │  │ RetryPolicy  │  │ TimeoutManager│      │
│  │ Pool         │  │              │  │               │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
├─────────────────────────────────────────────────────────────┤
│  Platform Layer (Winsock2 / BSD Sockets)                   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic GET Request

```cpp
#include "http_client.hpp"

using namespace rawrxd::benchmark;

// Create and initialize client
HttpClient client;
client.Initialize();

// Simple GET request
HttpResponse response = client.Get("http://api.example.com/data");

if (response.IsSuccess()) {
    std::cout << "Response: " << response.body << std::endl;
} else {
    std::cerr << "Error: " << response.error_message << std::endl;
}

// Cleanup
client.Shutdown();
```

### POST with JSON

```cpp
// POST with JSON body
std::string json_body = R"({"key": "value", "number": 42})";
HttpResponse response = client.PostJson(
    "http://api.example.com/submit",
    json_body
);

// Check status code
if (response.status_code == 201) {
    std::cout << "Created successfully" << std::endl;
}
```

### Custom Headers

```cpp
std::map<std::string, std::string> headers;
headers["Authorization"] = "Bearer token123";
headers["X-Request-ID"] = "uuid-456";

HttpResponse response = client.Get("http://api.example.com/protected", headers);
```

## Connection Pool

### Enabling Connection Pooling

```cpp
HttpClient client;
client.Initialize();

// Enable pool with max 10 connections
client.EnableConnectionPool(10);

// Requests will now reuse connections
HttpResponse r1 = client.Get("http://api.example.com/endpoint1");
HttpResponse r2 = client.Get("http://api.example.com/endpoint2");

// Get pool statistics
auto stats = client.GetStats();
std::cout << "Active connections: " << stats.active_connections << std::endl;
std::cout << "Idle connections: " << stats.idle_connections << std::endl;

// Disable when done
client.DisableConnectionPool();
```

### Pool Configuration

```cpp
// Custom pool settings
ConnectionPool pool(
    20,     // max_connections
    5000,   // connection_timeout_ms
    30000   // idle_timeout_ms
);

// Acquire connection
auto conn = pool.Acquire("api.example.com", 80);
if (conn) {
    // Use connection...
    
    // Release back to pool
    pool.Release(conn);
}
```

## Request/Response

### HttpRequest Structure

```cpp
HttpRequest request;
request.method = "POST";
request.url = "http://api.example.com/v1/resource";
request.body = "request data";

// Set custom headers
request.SetHeader("Content-Type", "application/json");
request.SetHeader("Accept", "application/json");

// Set timeouts (milliseconds)
request.connect_timeout_ms = 5000;
request.read_timeout_ms = 30000;
request.total_timeout_ms = 60000;

// Execute request
HttpResponse response = client.Request(request);
```

### HttpResponse Structure

```cpp
struct HttpResponse {
    int status_code = 0;                    // HTTP status code
    std::string status_text;                 // Status text (e.g., "OK")
    std::map<std::string, std::string> headers;
    std::string body;                        // Response body
    double latency_ms = 0.0;                  // Request latency
    bool success = false;                     // Success flag
    std::string error_message;               // Error description
    
    // Helper methods
    bool IsSuccess() const;                  // 200-299 status
    bool IsRedirect() const;                 // 300-399 status
    bool IsClientError() const;              // 400-499 status
    bool IsServerError() const;              // 500-599 status
    bool HasHeader(const std::string& name) const;
    std::string GetHeader(const std::string& name) const;
};
```

## Retry Policies

### Default Retry Policy

```cpp
HttpClient client;
client.Initialize();

// Set retry policy: 3 retries, 1 second base delay, exponential backoff
client.SetRetryPolicy(3, 1000, true);

// Requests will automatically retry on:
// - 5xx server errors
// - 429 Too Many Requests
// - 408 Request Timeout
// - Connection failures
```

### Custom Retry Policy

```cpp
// Create custom retry policy
RetryPolicy policy(
    5,          // max_retries
    500,        // base_delay_ms
    true,       // exponential_backoff
    2.0,        // backoff_multiplier
    30000       // max_delay_ms
);

// Check if error is retryable
HttpResponse response;
response.status_code = 503;
bool should_retry = policy.IsRetryableError(response);

// Get delay for attempt
int delay_ms = policy.GetDelayMs(2);  // 3rd attempt (0-indexed)
```

### Retryable Errors

The following HTTP status codes are considered retryable:

| Status Code | Description | Retryable |
|-------------|-------------|-----------|
| 408 | Request Timeout | Yes |
| 429 | Too Many Requests | Yes |
| 500 | Internal Server Error | Yes |
| 502 | Bad Gateway | Yes |
| 503 | Service Unavailable | Yes |
| 504 | Gateway Timeout | Yes |
| 400 | Bad Request | No |
| 401 | Unauthorized | No |
| 403 | Forbidden | No |
| 404 | Not Found | No |

## Timeout Management

### Global Timeouts

```cpp
HttpClient client;
client.Initialize();

// Set default timeouts for all requests
client.SetDefaultTimeout(
    5000,   // connect_timeout_ms
    30000,  // read_timeout_ms
    60000   // total_timeout_ms
);
```

### Per-Request Timeouts

```cpp
HttpRequest request;
request.url = "http://slow-api.example.com/data";
request.connect_timeout_ms = 10000;  // 10 seconds
request.read_timeout_ms = 120000;     // 2 minutes
request.total_timeout_ms = 300000;    // 5 minutes

HttpResponse response = client.Request(request);
```

### TimeoutManager

```cpp
// Create timeout manager
TimeoutManager timeout_mgr(
    5000,   // connect_ms
    30000,  // read_ms
    60000   // total_ms
);

// Apply to socket
timeout_mgr.SetSocketTimeouts(socket_fd);

// Check if timed out
if (timeout_mgr.IsTimedOut()) {
    // Handle timeout
}

// Get remaining time
int remaining_ms = timeout_mgr.GetRemainingTimeMs();
```

## Error Handling

### Response Validation

```cpp
HttpResponse response = client.Get("http://api.example.com/data");

if (!response.success) {
    // Handle error
    std::cerr << "Request failed: " << response.error_message << std::endl;
    return;
}

if (response.IsClientError()) {
    // 4xx error - client issue
    std::cerr << "Client error: " << response.status_code << std::endl;
    return;
}

if (response.IsServerError()) {
    // 5xx error - server issue (may be retryable)
    std::cerr << "Server error: " << response.status_code << std::endl;
    return;
}

// Success!
ProcessResponse(response.body);
```

### Exception Safety

The HTTP client uses error codes rather than exceptions for transport errors:

```cpp
// This will not throw for HTTP errors
HttpResponse response = client.Get("http://api.example.com/data");

// Check success flag
if (!response.success) {
    // Handle transport error (DNS, connection, etc.)
}

// Check HTTP status
if (response.status_code != 200) {
    // Handle HTTP error
}
```

## Advanced Usage

### Statistics Tracking

```cpp
HttpClient client;
client.Initialize();

// Make some requests...
client.Get("http://api.example.com/endpoint1");
client.Get("http://api.example.com/endpoint2");
client.Post("http://api.example.com/endpoint3", "data");

// Get statistics
auto stats = client.GetStats();
std::cout << "Total requests: " << stats.total_requests << std::endl;
std::cout << "Successful: " << stats.successful_requests << std::endl;
std::cout << "Failed: " << stats.failed_requests << std::endl;
std::cout << "Retried: " << stats.retried_requests << std::endl;
std::cout << "Avg latency: " << stats.average_latency_ms << " ms" << std::endl;
std::cout << "Min latency: " << stats.min_latency_ms << " ms" << std::endl;
std::cout << "Max latency: " << stats.max_latency_ms << " ms" << std::endl;

// Reset statistics
client.ResetStats();
```

### URL Utilities

```cpp
// URL encoding
std::string encoded = http::UrlEncode("hello world");
// Result: "hello%20world"

// URL decoding
std::string decoded = http::UrlDecode("hello%20world");
// Result: "hello world"

// Header normalization
std::string normalized = http::NormalizeHeaderName("content-type");
// Result: "Content-Type"

// Status text lookup
const char* status_text = http::GetStatusText(404);
// Result: "Not Found"

// Status code classification
bool is_success = http::IsSuccess(200);           // true
bool is_redirect = http::IsRedirect(301);         // true
bool is_client_error = http::IsClientError(404);  // true
bool is_server_error = http::IsServerError(500);  // true
```

### URL Parsing

```cpp
std::string host, path;
int port;
bool use_https;

bool success = HttpClient::ParseUrl(
    "https://api.example.com:8443/v1/resource",
    host, port, path, use_https
);

// Results:
// host = "api.example.com"
// port = 8443
// path = "/v1/resource"
// use_https = true
```

## Platform Notes

### Windows

- Uses Winsock2 for socket operations
- Requires `ws2_32.lib` to be linked
- Automatically handles WSAStartup/WSACleanup

### Linux

- Uses BSD sockets
- No additional libraries required
- Supports non-blocking I/O with fcntl

### macOS

- Uses BSD sockets (similar to Linux)
- May require CoreFoundation for some features

## Performance Tips

1. **Use Connection Pooling**: Enable connection pooling for multiple requests to the same host
2. **Set Appropriate Timeouts**: Balance between reliability and responsiveness
3. **Configure Retry Policies**: Use exponential backoff to avoid overwhelming servers
4. **Reuse HttpClient**: Initialize once and reuse for multiple requests
5. **Monitor Statistics**: Track latency and error rates for optimization

## Thread Safety

The HttpClient is **not** thread-safe. For multi-threaded applications:

```cpp
// Create separate client per thread
void ThreadFunc() {
    HttpClient client;
    client.Initialize();
    // ... use client ...
    client.Shutdown();
}

// Or use thread-local storage
thread_local HttpClient tls_client;
```

ConnectionPool is thread-safe and can be shared between threads.

## Examples

See the `examples/` directory for complete working examples:

- `basic_request.cpp` - Simple GET/POST requests
- `connection_pool.cpp` - Connection pooling demonstration
- `retry_handling.cpp` - Retry policy configuration
- `benchmark_client.cpp` - High-performance benchmarking example

## See Also

- [Backend Adapter Guide](backend_adapter_guide.md)
- [Configuration Reference](configuration_reference.md)
- [Troubleshooting Guide](troubleshooting.md)
