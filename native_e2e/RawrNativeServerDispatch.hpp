// RawrNativeServerDispatch.hpp — early /api/native/* intercept + route witnesses
#pragma once
#include "rawr_native_e2e_abi.h"
#include <string>

namespace RawrNativeE2E {

inline void RegisterLiveAttachments() {
    // Only routes that are actually installed on this process.
    RawrNative_RegisterRouteAttachment("/status", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/status", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/health", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/generate", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/v1/chat/completions", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/ask", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/api/model/load", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/api/model/unload", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/api/model/profiles", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/engine/capabilities", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/hotpatch/status", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/nvme/bunnyhop/status", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/api/nvme/bunnyhop/arm", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/api/nvme/bunnyhop/disarm", RN_HTTP_POST);
    RawrNative_RegisterRouteAttachment("/gui", RN_HTTP_GET);
    RawrNative_RegisterRouteAttachment("/models", RN_HTTP_GET);
}

// Returns true if request was fully handled (caller should send json and return).
inline bool TryHandle(const std::string& method, const std::string& path,
                      const std::string& body, std::string& outJson,
                      uint32_t& outStatus) {
    static bool once = false;
    if (!once) { RegisterLiveAttachments(); once = true; }

    char buf[65536];
    uint32_t st = 0;
    if (!RawrNative_HandleHttp(method.c_str(), path.c_str(), body.c_str(),
                               buf, sizeof(buf), &st))
        return false;
    outJson.assign(buf);
    outStatus = st;
    return true;
}

inline std::string HttpResponse(uint32_t status, const std::string& json) {
    std::string r = "HTTP/1.1 " + std::to_string(status) + " OK\r\n";
    if (status == 400) r = "HTTP/1.1 400 Bad Request\r\n";
    else if (status == 404) r = "HTTP/1.1 404 Not Found\r\n";
    else if (status == 503) r = "HTTP/1.1 503 Service Unavailable\r\n";
    else if (status >= 400) r = "HTTP/1.1 " + std::to_string(status) + " Error\r\n";
    r += "Content-Type: application/json\r\n";
    r += "Access-Control-Allow-Origin: *\r\n";
    r += "Content-Length: " + std::to_string(json.size()) + "\r\n\r\n";
    r += json;
    return r;
}

} // namespace RawrNativeE2E
