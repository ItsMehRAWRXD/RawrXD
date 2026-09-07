// rawr_term_host_main.cpp
#include "rawr_terminal_host.hpp"
#include <cstdio>

int main() {
    fprintf(stderr, "rawr_terminal_host listening on %s\n",
            rawr::term::HostPipeName());
    return rawr::term::RunTerminalHost(0);
}
