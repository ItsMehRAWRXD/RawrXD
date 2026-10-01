#include "cfix/config_loader.h"

#include <sstream>

namespace cfix {

namespace {

std::string trim(const std::string& s) {
    size_t begin = 0;
    size_t end = s.size();
    while (begin < end && (s[begin] == ' ' || s[begin] == '\t' || s[begin] == '\r' || s[begin] == '\n')) {
        ++begin;
    }
    while (end > begin && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        --end;
    }
    return s.substr(begin, end - begin);
}

int parse_int(const std::string& raw) {
    std::istringstream in(raw);
    int value = 0;
    in >> value;
    return value;
}

}  // namespace

Config load_config(const std::string& text) {
    Config cfg;

    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        const size_t eq = trimmed.find('=');
        if (eq == std::string::npos) {
            continue;
        }

        const std::string key = trim(trimmed.substr(0, eq));
        const std::string value = trim(trimmed.substr(eq + 1));

        if (key == "host") {
            cfg.host = value;
        } else if (key == "port") {
            cfg.port = parse_int(value);
        } else if (key == "verbose") {
            cfg.verbose = (value == "true");
        }
    }

    return cfg;
}

}  // namespace cfix
