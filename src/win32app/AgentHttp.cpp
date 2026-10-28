#include "Win32IDE.h"
#include "AgentProduct.hpp"
#include "../product/gateway/product_deep2_infer.hpp"
#include <sstream>

static void SendJson(SOCKET client, int code, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << code << " X\r\nContent-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\nConnection: close\r\n\r\n" << body;
    std::string msg = oss.str();
    int left = static_cast<int>(msg.size());
    const char* p = msg.data();
    while (left > 0) {
        int n = send(client, p, left, 0);
        if (n <= 0) return;
        p += n;
        left -= n;
    }
}

void Win32IDE::handleAgentRun(SOCKET client, const std::string& body) {
    bool ready = !m_loadedModelPath.empty() || rawr::ProductSessionOpen();
    void* mgr = m_agenticBridge ? m_agenticBridge->GetSubAgentManager() : nullptr;
    std::string out;
    int code = AgentHttpRun(body, ready, mgr, &out);
    SendJson(client, code, out);
}
