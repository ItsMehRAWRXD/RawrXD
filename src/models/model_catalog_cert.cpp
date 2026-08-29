#include "ModelCatalog.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using rawrxd::models::ModelCatalog;
using rawrxd::models::storageKindName;

static void setRoot(const std::string& root) {
#ifdef _WIN32
    _putenv_s("RAWRXD_MODEL_ROOT", root.c_str());
#else
    setenv("RAWRXD_MODEL_ROOT", root.c_str(), 1);
#endif
    ModelCatalog::instance().setAdditionalRoots({fs::path(root)}, true);
}

int main(int argc, char** argv) {
    try {
        std::string spec;
        std::string root;
        bool list = false;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            auto value = [&](const char* flag) -> std::string {
                if (++i >= argc) {
                    throw std::runtime_error(std::string("missing value for ") + flag);
                }
                return argv[i];
            };

            if (a == "--model") spec = value("--model");
            else if (a == "--root") root = value("--root");
            else if (a == "--list") list = true;
            else if (a == "--help" || a == "-h") {
                std::cout
                    << "rawrxd_model_catalog_cert "
                    << "[--root G:\\OllamaModels] [--list] [--model spec]\n";
                return 0;
            } else {
                throw std::runtime_error("unknown argument: " + a);
            }
        }

        if (!root.empty()) setRoot(root);

        std::cout << "[MODEL_ROOTS]\n";
        for (const auto& r : ModelCatalog::roots()) {
            std::error_code ec;
            std::cout << r.string()
                      << " exists=" << (fs::exists(r, ec) && !ec ? "yes" : "no")
                      << "\n";
        }

        if (list) {
            std::cout << "\n[MODELS]\n";
            for (const auto& m : ModelCatalog::list()) {
                const auto& p = m.path.empty() ? m.absolutePath : m.path;
                std::cout << (m.name.empty() ? m.displayName : m.name)
                          << "\t" << storageKindName(m.storageKind)
                          << "\t" << p.string();
                if (!m.sha256.empty()) std::cout << "\tsha256:" << m.sha256;
                std::cout << "\n";
            }
        }

        if (spec.empty()) {
            std::cout << "\nMODEL-CATALOG-001=DISCOVERY_PASS\n";
            return 0;
        }

        const auto hit = ModelCatalog::resolve(spec);
        if (!hit) {
            std::cerr << "MODEL-CATALOG-001=FAIL\n"
                      << "reason=unresolved\n"
                      << "spec=" << spec << "\n";
            return 2;
        }

        const auto& p = hit->path.empty() ? hit->absolutePath : hit->path;
        std::cout << "\n[RESOLVED]\n"
                  << "spec=" << spec << "\n"
                  << "display_name=" << hit->displayName << "\n"
                  << "path=" << p.string() << "\n"
                  << "kind=" << storageKindName(hit->storageKind) << "\n"
                  << "blob_offset=" << hit->blobOffset << "\n"
                  << "sha256=" << hit->sha256 << "\n"
                  << "manifest=" << hit->manifestPath.string() << "\n"
                  << "MODEL-CATALOG-001=PASS\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "MODEL-CATALOG-001=FAIL\nreason=" << ex.what() << "\n";
        return 1;
    }
}
