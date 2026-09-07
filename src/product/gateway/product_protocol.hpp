#pragma once
#include <cstring>
#include <string>
namespace rawr::product {

struct ProductCmd {
    std::string verb;
    std::string arg;
    int ok = 0;
};

inline ProductCmd ParseProductCmd(const std::string& line) {
    ProductCmd c;
    auto sp = line.find(' ');
    c.verb = sp == std::string::npos ? line : line.substr(0, sp);
    c.arg = sp == std::string::npos ? "" : line.substr(sp + 1);
    c.ok = !c.verb.empty() ? 1 : 0;
    return c;
}

inline std::string HandleProductCmd(const ProductCmd& c) {
    if (c.verb == "PING") return "PONG abi=1 caps=63";
    if (c.verb == "CAPS") return "63";
    if (c.verb == "STATUS") return "idle";
    if (c.verb == "COMPLETE") return "queued";
    if (c.verb == "INDEX") return "queued";
    return "ERR unknown";
}

} // namespace rawr::product
