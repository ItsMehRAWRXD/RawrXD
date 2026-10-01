#pragma once

#include <stdexcept>
#include <string>

namespace cfix {

struct Config {
    std::string host;
    int port = 0;
    bool verbose = false;
};

// Parses a simple "key=value" configuration line.
//
// Contract (as documented in docs/config_format.md):
//   * `host` must be non-empty
//   * `port` must be an integer in the range 1..65535
//   * `verbose` is `true` or `false`
//
// Throws std::invalid_argument when the input violates the contract.
Config load_config(const std::string& text);

}  // namespace cfix
