// RawrXD local extension CLI: executes no untrusted extension JS and requires no model.
#include "../src/win32app/OfflineExtensionStore.h"
#include <iostream>
#include <string>

using RawrXD::OfflineExtensions::Store;

static int usage() {
    std::cerr << "Usage: rawrxd-extensions [--root DIR] [--approve-mutations] "
                 "list|info ID|install DIRECTORY|update DIRECTORY|enable ID|disable ID|remove ID|recover\n";
    return 2;
}
int main(int argc, char** argv) {
    try {
        int i = 1;
        std::string root = RawrXD::OfflineExtensions::defaultRoot().string();
        bool approveMutations = false;
        while (i < argc) {
            if (std::string(argv[i]) == "--root") {
                if (++i >= argc) return usage();
                root = argv[i++];
            } else if (std::string(argv[i]) == "--approve-mutations") {
                approveMutations = true;
                ++i;
            } else break;
        }
        if (i >= argc) return usage();
        const std::string command = argv[i++];
        const bool withoutArg = command == "list" || command == "recover";
        const bool withArg = command == "info" || command == "install" ||
                             command == "update" || command == "enable" ||
                             command == "disable" || command == "remove";
        if ((!withArg && !withoutArg) ||
            (withoutArg && i != argc) || (withArg && i + 1 != argc))
            return usage();
        const bool mutation = command == "install" || command == "update" ||
                              command == "enable" || command == "disable" ||
                              command == "remove" || command == "recover";
        if (mutation && !approveMutations) {
            std::cerr << "ERROR: --approve-mutations required for filesystem changes\n";
            return 3;
        }
        Store store(root);
        const std::string arg = withArg ? argv[i] : "";
        // Tabular CLI output must not permit manifest-controlled newlines or
        // tabs to forge additional rows/columns in caller-visible results.
        auto safeField = [](std::string field) {
            for (char& ch : field) {
                if (static_cast<unsigned char>(ch) < 0x20 || ch == 0x7f)
                    ch = ' ';
            }
            return field;
        };
        auto show = [&](const RawrXD::OfflineExtensions::Extension& e) {
            std::cout << e.id << '\t' << e.version << '\t'
                      << (e.enabled ? "enabled" : "disabled") << '\t'
                      << safeField(e.description) << '\n';
        };
        if (command == "list") {
            for (const auto& e : store.list()) show(e);
        } else if (command == "info") show(store.get(arg));
        else if (command == "install") show(store.install(arg));
        else if (command == "update") show(store.update(arg));
        else if (command == "enable") show(store.setEnabled(arg, true));
        else if (command == "disable") show(store.setEnabled(arg, false));
        else if (command == "remove") {
            store.remove(arg); std::cout << "removed\t" << arg << '\n';
        } else if (command == "recover") {
            std::cout << "recovered\t" << store.recover() << '\n';
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return 1;
    }
}
