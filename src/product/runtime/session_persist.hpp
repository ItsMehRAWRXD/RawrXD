#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct ProductSession {
    std::string id;
    std::string workspace;
    std::string lastPrompt;
    std::string lastText;
    uint64_t gen = 0;
    int crashRecovered = 0;
};

inline std::string ProductSessionRoot() {
    return "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_SESSIONS";
}

inline void ProductSessionEnsure() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(ProductSessionRoot().c_str(), nullptr);
#endif
}

inline std::string ProductSessionPath(const std::string& id) {
    return ProductSessionRoot() + "\\" + id + ".psess";
}

inline bool SaveProductSession(const ProductSession& s) {
    ProductSessionEnsure();
    std::ofstream out(ProductSessionPath(s.id), std::ios::binary);
    if (!out) return false;
    out << "id=" << s.id << "\nws=" << s.workspace << "\ngen=" << s.gen
        << "\ncrash=" << s.crashRecovered << "\nprompt=" << s.lastPrompt
        << "\ntext=" << s.lastText << "\n";
    return true;
}

inline bool LoadProductSession(const std::string& id, ProductSession& s) {
    std::ifstream in(ProductSessionPath(id), std::ios::binary);
    if (!in) return false;
    s = {};
    s.id = id;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("ws=", 0) == 0) s.workspace = line.substr(3);
        else if (line.rfind("gen=", 0) == 0) s.gen = (uint64_t)atoll(line.c_str() + 4);
        else if (line.rfind("crash=", 0) == 0) s.crashRecovered = atoi(line.c_str() + 6);
        else if (line.rfind("prompt=", 0) == 0) s.lastPrompt = line.substr(7);
        else if (line.rfind("text=", 0) == 0) s.lastText = line.substr(5);
    }
    return true;
}

inline std::string NewProductSessionId() {
    char buf[48];
    snprintf(buf, sizeof(buf), "psess_%llu", (unsigned long long)time(nullptr));
    return buf;
}

} // namespace rawr::product
