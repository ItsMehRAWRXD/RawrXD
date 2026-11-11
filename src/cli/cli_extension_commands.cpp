// ============================================================================
//  VS Code extension commands for the RawrXD command line.
//
//  The extension runtime is shared with the GUI: this file is a thin adapter
//  over the same marketplace and extension host that the Win32 IDE uses, so
//  an extension installed from the command line is visible to the IDE and
//  vice versa.
//
//      rawr plugin list
//      rawr plugin installed
//      rawr plugin install <vsix-path>
//      rawr plugin load <extension-id>
//      rawr plugin unload <extension-id>
//      rawr plugin enable <extension-id>
//      rawr plugin disable <extension-id>
//      rawr plugin uninstall <extension-id>
//      rawr plugin search <query>
//      rawr plugin sync
//      rawr plugin help
// ============================================================================

#include "../marketplace/extension_marketplace.hpp"
#include "../marketplace/extension_auto_installer.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace RawrXD {
namespace CLI {

namespace {

std::vector<std::string> SplitWords(const std::string& text) {
    std::vector<std::string> words;
    std::istringstream stream(text);
    std::string word;
    while (stream >> word) words.push_back(word);
    return words;
}

void PrintUsage() {
    std::cout
        << "rawr plugin - VS Code extension management\n"
        << "\n"
        << "Usage:\n"
        << "  rawr plugin list                    list every known extension\n"
        << "  rawr plugin installed               list installed extensions\n"
        << "  rawr plugin install <vsix-path>     install a local .vsix package\n"
        << "  rawr plugin load <extension-id>     install and activate an extension\n"
        << "  rawr plugin unload <extension-id>   deactivate an extension\n"
        << "  rawr plugin enable <extension-id>   enable an installed extension\n"
        << "  rawr plugin disable <extension-id>  disable an installed extension\n"
        << "  rawr plugin uninstall <extension-id> remove an extension\n"
        << "  rawr plugin search <query>          search the marketplace\n"
        << "  rawr plugin sync                    refresh the marketplace index\n"
        << "  rawr plugin help                    show this message\n";
}

void PrintManifest(const Extensions::ExtensionManifest& manifest) {
    std::cout << "  " << manifest.id;
    if (!manifest.version.empty()) std::cout << "  v" << manifest.version;
    if (!manifest.displayName.empty()) std::cout << "  " << manifest.displayName;
    if (manifest.isEnabled) std::cout << "  [enabled]";
    if (manifest.isBuiltIn) std::cout << "  [built-in]";
    std::cout << "\n";
}

int ReportResult(const Extensions::ExtResult& result) {
    if (result.success) {
        if (!result.detail.empty()) std::cout << result.detail << "\n";
        return 0;
    }
    std::cerr << "error: " << result.detail << "\n";
    if (result.errorCode != 0) {
        std::cerr << "  code " << result.errorCode << "\n";
    }
    return 1;
}

} // namespace

// Handles a `rawr plugin ...` command line. `input` is everything after the
// word "plugin". Returns a process exit code.
bool handlePluginCommand(const std::string& input) {
    std::vector<std::string> words = SplitWords(input);
    if (words.empty()) {
        PrintUsage();
        return true;
    }

    const std::string& action = words[0];
    std::string argument;
    if (words.size() > 1) {
        for (size_t i = 1; i < words.size(); ++i) {
            if (i > 1) argument += " ";
            argument += words[i];
        }
    }

    Extensions::ExtensionMarketplace& marketplace = Extensions::ExtensionMarketplace::instance();

    if (action == "help" || action == "--help" || action == "-h") {
        PrintUsage();
        return true;
    }

    if (action == "list") {
        std::vector<Extensions::ExtensionManifest> manifests = marketplace.listInstalled();
        if (manifests.empty()) {
            std::cout << "no extensions are installed\n";
        } else {
            std::cout << manifests.size() << " extension(s):\n";
            for (const auto& manifest : manifests) PrintManifest(manifest);
        }
        return true;
    }

    if (action == "installed") {
        std::vector<Extensions::ExtensionManifest> manifests = marketplace.listInstalled();
        if (manifests.empty()) {
            std::cout << "no extensions are installed\n";
        } else {
            for (const auto& manifest : manifests) PrintManifest(manifest);
        }
        return true;
    }

    if (action == "enabled") {
        std::vector<Extensions::ExtensionManifest> manifests = marketplace.listEnabled();
        if (manifests.empty()) {
            std::cout << "no extensions are enabled\n";
        } else {
            for (const auto& manifest : manifests) PrintManifest(manifest);
        }
        return true;
    }

    if (action == "install") {
        if (argument.empty()) {
            std::cerr << "error: install requires a .vsix path\n";
            return true;
        }
        Extensions::ExtResult result = marketplace.installFromVsix(argument);
        ReportResult(result);
        return true;
    }

    if (action == "load") {
        if (argument.empty()) {
            std::cerr << "error: load requires an extension id\n";
            return true;
        }
        Extensions::ExtResult result = marketplace.installWithDependencies(argument);
        if (result.success) {
            result = marketplace.activate(argument);
        }
        ReportResult(result);
        return true;
    }

    if (action == "unload") {
        if (argument.empty()) {
            std::cerr << "error: unload requires an extension id\n";
            return true;
        }
        ReportResult(marketplace.deactivate(argument));
        return true;
    }

    if (action == "enable") {
        if (argument.empty()) {
            std::cerr << "error: enable requires an extension id\n";
            return true;
        }
        ReportResult(marketplace.enable(argument));
        return true;
    }

    if (action == "disable") {
        if (argument.empty()) {
            std::cerr << "error: disable requires an extension id\n";
            return true;
        }
        ReportResult(marketplace.disable(argument));
        return true;
    }

    if (action == "uninstall") {
        if (argument.empty()) {
            std::cerr << "error: uninstall requires an extension id\n";
            return true;
        }
        ReportResult(marketplace.uninstall(argument));
        return true;
    }

    if (action == "search") {
        Extensions::ExtensionSearchQuery query;
        query.text = argument;
        Extensions::ExtensionSearchResponse response;
        Extensions::ExtResult result = marketplace.search(query, response);
        if (!result.success) {
            ReportResult(result);
            return true;
        }
        if (response.results.empty()) {
            std::cout << "no extensions matched\n";
        } else {
            for (const auto& item : response.results) {
                std::cout << "  " << item.manifest.id;
                if (!item.manifest.displayName.empty()) {
                    std::cout << "  " << item.manifest.displayName;
                }
                if (!item.manifest.version.empty()) {
                    std::cout << "  v" << item.manifest.version;
                }
                std::cout << "\n";
            }
        }
        return true;
    }

    if (action == "sync") {
        ReportResult(marketplace.updateAll());
        return true;
    }

    std::cerr << "error: unknown plugin action '" << action << "'\n";
    PrintUsage();
    return true;
}

} // namespace CLI
} // namespace RawrXD
