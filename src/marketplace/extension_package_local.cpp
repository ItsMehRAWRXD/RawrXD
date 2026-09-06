// extension_package_local.cpp — top-25 IDE package install (no cloud/HTTP).
#include "extension_package_local.hpp"
#include "../win32app/VSIXInstaller.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace Extensions {
namespace Local {

namespace {

static const IdeExtensionFormatInfo kCatalog[kTopIdeExtensionCatalogCount] = {
    {"Visual Studio", ExtensionPackageFormat::VisualStudioVsix, ".vsix",
     "extension.vsixmanifest", true, false},
    {"VS Code", ExtensionPackageFormat::VsCodeVsix, ".vsix", "package.json", true, true},
    {"IntelliJ IDEA", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"PyCharm", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"WebStorm", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"Android Studio", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"Xcode", ExtensionPackageFormat::XcodeBundle, ".appex,.plugin", "Info.plist", true, false},
    {"Eclipse", ExtensionPackageFormat::EclipseBundle, ".jar,.zip", "plugin.xml", true, false},
    {"CLion", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"PhpStorm", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"GoLand", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"Sublime Text", ExtensionPackageFormat::SublimePackage, ".sublime-package",
     "*.sublime-package", true, false},
    {"Zed", ExtensionPackageFormat::ZedExtension, ".zip,.tar.gz", "extension.toml", true, false},
    {"Fleet", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"Cursor", ExtensionPackageFormat::VsCodeVsix, ".vsix", "package.json", true, true},
    {"Neovim", ExtensionPackageFormat::NeovimPack, ".zip,.tar.gz,.git", "plugin/,lua/", true, false},
    {"GNU Emacs", ExtensionPackageFormat::EmacsPackage, ".tar,.el,.tar.gz", "*-pkg.el", true, false},
    {"Rider", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"RubyMine", ExtensionPackageFormat::JetBrainsPlugin, ".zip,.jar",
     "META-INF/plugin.xml", true, false},
    {"NetBeans", ExtensionPackageFormat::NetBeansNBM, ".nbm,.jar", "Info/info.xml", true, false},
    {"Qt Creator", ExtensionPackageFormat::QtCreatorPlugin, ".dll,.zip", "plugin.json", true, false},
    {"Nova", ExtensionPackageFormat::NovaExtension, ".novaextension", "extension.json", true, false},
    {"Windsurf", ExtensionPackageFormat::VsCodeVsix, ".vsix", "package.json", true, true},
    {"VSCodium", ExtensionPackageFormat::VsCodeVsix, ".vsix", "package.json", true, true},
    {"Lapce", ExtensionPackageFormat::LapcePlugin, ".zip,.toml", "plugin.toml", true, false},
};

std::string lowerExt(const std::string& path) {
    std::string ext = fs::path(path).extension().string();
    for (auto& c : ext)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return ext;
}

bool extractArchive(const std::string& src, const std::string& dest) {
    fs::create_directories(dest);
    std::string ps = "powershell -NoProfile -Command \"Expand-Archive -LiteralPath '" + src +
                     "' -DestinationPath '" + dest + "' -Force\"";
    if (std::system(ps.c_str()) == 0)
        return true;
    std::string tar = "tar -xf \"" + src + "\" -C \"" + dest + "\"";
    return std::system(tar.c_str()) == 0;
}

void refineFormat(const std::string& dir, ExtensionPackageFormat& fmt) {
    if (fs::exists(dir + "/META-INF/plugin.xml"))
        fmt = ExtensionPackageFormat::JetBrainsPlugin;
    else if (fs::exists(dir + "/extension.toml"))
        fmt = ExtensionPackageFormat::ZedExtension;
    else if (fs::exists(dir + "/plugin.toml"))
        fmt = ExtensionPackageFormat::LapcePlugin;
    else if (fs::exists(dir + "/package.json") || fs::exists(dir + "/extension/package.json"))
        fmt = ExtensionPackageFormat::VsCodeVsix;
    else if (fs::exists(dir + "/extension.vsixmanifest"))
        fmt = ExtensionPackageFormat::VisualStudioVsix;
    else if (fs::exists(dir + "/plugin.xml"))
        fmt = ExtensionPackageFormat::EclipseBundle;
    else if (fs::exists(dir + "/Info/info.xml"))
        fmt = ExtensionPackageFormat::NetBeansNBM;
    else if (fs::exists(dir + "/Info.plist"))
        fmt = ExtensionPackageFormat::XcodeBundle;
    else if (fs::exists(dir + "/plugin.json"))
        fmt = ExtensionPackageFormat::QtCreatorPlugin;
    else if (fs::exists(dir + "/extension.json"))
        fmt = ExtensionPackageFormat::NovaExtension;
    else if (fs::exists(dir + "/plugin") || fs::exists(dir + "/lua"))
        fmt = ExtensionPackageFormat::NeovimPack;
}

std::string readTextFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void parseVsCodeManifest(const std::string& path, ExtensionManifest& m) {
    std::string content = readTextFile(path);
    if (content.empty()) return;
    auto field = [&](const char* key) -> std::string {
        std::string needle = std::string("\"") + key + "\"";
        auto p = content.find(needle);
        if (p == std::string::npos) return {};
        p = content.find(':', p);
        if (p == std::string::npos) return {};
        p = content.find('"', p);
        if (p == std::string::npos) return {};
        auto e = content.find('"', p + 1);
        if (e == std::string::npos) return {};
        return content.substr(p + 1, e - p - 1);
    };
    m.name = field("name");
    m.publisher = field("publisher");
    m.version = field("version");
    m.displayName = field("displayName");
    m.description = field("description");
    if (!m.publisher.empty() && !m.name.empty())
        m.id = m.publisher + "." + m.name;
}

std::string safeDirName(const std::string& id, const std::string& fallback) {
    std::string out = id.empty() ? fallback : id;
    for (char& c : out) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|')
            c = '_';
    }
    return out;
}

}  // namespace

const IdeExtensionFormatInfo* IdeCatalog(size_t& outCount) {
    outCount = kTopIdeExtensionCatalogCount;
    return kCatalog;
}

const char* FormatName(ExtensionPackageFormat fmt) {
    switch (fmt) {
    case ExtensionPackageFormat::VsCodeVsix: return "VS Code VSIX";
    case ExtensionPackageFormat::VisualStudioVsix: return "Visual Studio VSIX";
    case ExtensionPackageFormat::JetBrainsPlugin: return "JetBrains Plugin";
    case ExtensionPackageFormat::EclipseBundle: return "Eclipse Bundle";
    case ExtensionPackageFormat::SublimePackage: return "Sublime Package";
    case ExtensionPackageFormat::NeovimPack: return "Neovim Pack";
    case ExtensionPackageFormat::EmacsPackage: return "Emacs Package";
    case ExtensionPackageFormat::XcodeBundle: return "Xcode Bundle";
    case ExtensionPackageFormat::NetBeansNBM: return "NetBeans NBM";
    case ExtensionPackageFormat::ZedExtension: return "Zed Extension";
    case ExtensionPackageFormat::QtCreatorPlugin: return "Qt Creator Plugin";
    case ExtensionPackageFormat::NovaExtension: return "Nova Extension";
    case ExtensionPackageFormat::AtomPackage: return "Atom Package";
    case ExtensionPackageFormat::LapcePlugin: return "Lapce Plugin";
    case ExtensionPackageFormat::NativeDll: return "Native DLL";
    case ExtensionPackageFormat::RawrPlugin: return "RawrXD Plugin";
    case ExtensionPackageFormat::PythonWheel: return "Python Wheel";
    case ExtensionPackageFormat::JsModule: return "JS Module";
    default: return "Unknown";
    }
}

ExtensionPackageFormat DetectFormat(const std::string& packagePath) {
    if (!fs::exists(packagePath))
        return ExtensionPackageFormat::Unknown;

    std::string ext = lowerExt(packagePath);
    if (ext == ".dll") return ExtensionPackageFormat::NativeDll;
    if (ext == ".rawrpkg") return ExtensionPackageFormat::RawrPlugin;
    if (ext == ".whl" || ext == ".egg") return ExtensionPackageFormat::PythonWheel;
    if (ext == ".js") return ExtensionPackageFormat::JsModule;
    if (ext == ".sublime-package") return ExtensionPackageFormat::SublimePackage;
    if (ext == ".nbm") return ExtensionPackageFormat::NetBeansNBM;
    if (ext == ".novaextension") return ExtensionPackageFormat::NovaExtension;
    if (ext == ".appex" || ext == ".plugin") return ExtensionPackageFormat::XcodeBundle;
    if (ext == ".el") return ExtensionPackageFormat::EmacsPackage;
    if (ext == ".vsix") return ExtensionPackageFormat::VsCodeVsix;
    if (ext == ".jar" || ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".tgz") {
        std::string stem = fs::path(packagePath).stem().string();
        for (auto& c : stem) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (stem.find("jetbrains") != std::string::npos || stem.find("intellij") != std::string::npos)
            return ExtensionPackageFormat::JetBrainsPlugin;
        if (stem.find("eclipse") != std::string::npos) return ExtensionPackageFormat::EclipseBundle;
        if (stem.find("zed") != std::string::npos) return ExtensionPackageFormat::ZedExtension;
        if (stem.find("lapce") != std::string::npos) return ExtensionPackageFormat::LapcePlugin;
        if (stem.find("nvim") != std::string::npos || stem.find("neovim") != std::string::npos)
            return ExtensionPackageFormat::NeovimPack;
        if (ext == ".jar") return ExtensionPackageFormat::EclipseBundle;
        return ExtensionPackageFormat::JetBrainsPlugin;
    }
    if (fs::is_directory(packagePath)) {
        if (fs::exists(packagePath + "/META-INF/plugin.xml"))
            return ExtensionPackageFormat::JetBrainsPlugin;
        if (fs::exists(packagePath + "/package.json"))
            return ExtensionPackageFormat::VsCodeVsix;
        if (fs::exists(packagePath + "/extension.toml"))
            return ExtensionPackageFormat::ZedExtension;
        if (fs::exists(packagePath + "/plugin.toml"))
            return ExtensionPackageFormat::LapcePlugin;
        if (fs::exists(packagePath + "/plugin") || fs::exists(packagePath + "/lua"))
            return ExtensionPackageFormat::NeovimPack;
    }
    return ExtensionPackageFormat::Unknown;
}

std::wstring BuildInstallFileFilter() {
    std::wstring filter =
        L"All supported IDE packages\0"
        L"*.vsix;*.zip;*.jar;*.nbm;*.sublime-package;*.novaextension;*.appex;*.plugin;"
        L"*.dll;*.rawrpkg;*.whl;*.js;*.el;*.tar;*.tar.gz;*.tgz\0"
        L"VS Code / Cursor / Windsurf (.vsix)\0*.vsix\0"
        L"JetBrains (.zip,.jar)\0*.zip;*.jar\0"
        L"Eclipse / NetBeans (.jar,.nbm)\0*.jar;*.nbm\0"
        L"Sublime (.sublime-package)\0*.sublime-package\0"
        L"Zed / Lapce / Neovim (.zip,.tar.gz)\0*.zip;*.tar.gz;*.tgz\0"
        L"Native / RawrXD (.dll,.rawrpkg)\0*.dll;*.rawrpkg\0"
        L"All Files (*.*)\0*.*\0\0";
    return filter;
}

ExtResult InstallPackage(const std::string& packagePath) {
    if (!fs::exists(packagePath))
        return ExtResult::error("Package not found", 2);

    ExtensionPackageFormat fmt = DetectFormat(packagePath);
    if (fmt == ExtensionPackageFormat::Unknown)
        return ExtResult::error("Unrecognized extension package format", 3);

    const std::string stem = fs::path(packagePath).stem().string();
    ExtensionManifest manifest;
    manifest.id = "imported." + stem;
    manifest.name = stem;
    manifest.version = "0.0.1";
    manifest.packageFormat = static_cast<uint32_t>(fmt);
    manifest.sourceIde = FormatName(fmt);
    manifest.isEnabled = true;

    const std::string root = RawrXD::GetExtensionsInstallRoot();
    fs::create_directories(root);
    std::string targetDir = root + safeDirName(manifest.id, stem) + "/";

    if (fmt == ExtensionPackageFormat::NativeDll || fmt == ExtensionPackageFormat::JsModule ||
        fmt == ExtensionPackageFormat::RawrPlugin || fmt == ExtensionPackageFormat::PythonWheel) {
        fs::create_directories(targetDir);
        fs::copy_file(packagePath, targetDir + fs::path(packagePath).filename().string(),
                      fs::copy_options::overwrite_existing);
    } else if (fs::is_directory(packagePath)) {
        fs::create_directories(targetDir);
        fs::copy(packagePath, targetDir,
                 fs::copy_options::recursive | fs::copy_options::overwrite_existing);
        refineFormat(targetDir, fmt);
    } else {
        if (!extractArchive(packagePath, targetDir))
            return ExtResult::error("Failed to extract package archive", 4);
        refineFormat(targetDir, fmt);
    }

    manifest.packageFormat = static_cast<uint32_t>(fmt);
    manifest.sourceIde = FormatName(fmt);

    std::string pkgJson = targetDir + "extension/package.json";
    if (!fs::exists(pkgJson)) pkgJson = targetDir + "package.json";
    if (fs::exists(pkgJson))
        parseVsCodeManifest(pkgJson, manifest);

    if (manifest.id.empty() || manifest.id == "imported.")
        manifest.id = "imported." + stem;

    const std::string finalDir = root + safeDirName(manifest.id, stem) + "/";
    if (finalDir != targetDir && fs::exists(targetDir)) {
        fs::create_directories(root);
        if (fs::exists(finalDir))
            fs::remove_all(finalDir);
        fs::rename(targetDir, finalDir);
        targetDir = finalDir;
    }

    {
        std::ofstream meta(targetDir + "rawrxd_package_format.txt");
        if (meta)
            meta << FormatName(static_cast<ExtensionPackageFormat>(manifest.packageFormat))
                 << "\nsource=" << manifest.sourceIde << "\n";
    }

    return ExtResult::ok(std::string("Installed ") + manifest.sourceIde + ": " + manifest.id);
}

}  // namespace Local
}  // namespace Extensions
}  // namespace RawrXD
