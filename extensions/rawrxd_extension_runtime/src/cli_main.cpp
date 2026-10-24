// The command line front end for the shared extension runtime.
//
//     rawr-plugin list
//     rawr-plugin installed
//     rawr-plugin install <vsix-path>
//     rawr-plugin load <extension-id>
//     rawr-plugin unload <extension-id>
//     rawr-plugin enable <extension-id>
//     rawr-plugin disable <extension-id>
//     rawr-plugin uninstall <extension-id>
//     rawr-plugin search <query>
//     rawr-plugin sync
//     rawr-plugin help
//
// Everything below the dispatch lives in the shared runtime, so the GUI and
// the command line behave identically.

#include <iostream>
#include <string>

namespace RawrXD {
namespace CLI {
int handlePluginCommand(const std::string& input);
}
}

int main(int argc, char** argv) {
    std::string input;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) input += " ";
        input += argv[i];
    }

    if (argc < 2) {
        return RawrXD::CLI::handlePluginCommand("help");
    }

    return RawrXD::CLI::handlePluginCommand(input);
}
