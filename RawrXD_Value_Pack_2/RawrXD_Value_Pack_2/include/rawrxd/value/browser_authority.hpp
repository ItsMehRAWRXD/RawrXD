#pragma once

#ifdef _WIN32

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::value {

struct BrowserResult {
    bool ok{false};
    std::string value;
    std::string error;
};

class BrowserAuthority {
public:
    BrowserAuthority();
    ~BrowserAuthority();

    BrowserAuthority(const BrowserAuthority&) = delete;
    BrowserAuthority& operator=(const BrowserAuthority&) = delete;

    bool launch(std::uint16_t debugging_port = 9222, bool headless = false);
    bool attach(std::uint16_t debugging_port = 9222);
    void close();

    BrowserResult navigate(const std::string& url, std::uint32_t timeout_ms = 20000);
    BrowserResult evaluate(const std::string& javascript, std::uint32_t timeout_ms = 10000);
    BrowserResult queryText(const std::string& selector);
    BrowserResult click(const std::string& selector);
    BrowserResult type(const std::string& selector, const std::string& text, bool clear_first = true);
    BrowserResult screenshot(const std::string& png_path);

    std::vector<std::string> takeConsoleEvents();
    std::vector<std::string> takeNetworkFailures();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace rawrxd::value

#endif // _WIN32
