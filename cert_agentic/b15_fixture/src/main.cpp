#include "cfix/config_loader.h"

#include <iostream>

int main() {
    const char* text =
        "# demo configuration\n"
        "host=127.0.0.1\n"
        "port=8080\n"
        "verbose=false\n";

    const cfix::Config cfg = cfix::load_config(text);

    std::cout << "host=" << cfg.host << "\n";
    std::cout << "port=" << cfg.portNumber() << "\n";
    std::cout << "verbose=" << (cfg.verbose ? "true" : "false") << "\n";

    return 0;
}
