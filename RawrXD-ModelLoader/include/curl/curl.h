#pragma once
#include <string>

// Curl stub for compilation without libcurl SDK
typedef void CURL;
typedef void* CURLcode;

typedef unsigned int (*curl_write_callback)(void*, unsigned int, unsigned int, void*);

class CURL_Easy {
public:
    CURL_Easy() {}
    ~CURL_Easy() {}
    
    bool Download(const std::string& url, const std::string& out_path) {
        return false;  // Stub implementation
    }
};
