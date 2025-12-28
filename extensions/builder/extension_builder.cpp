#include "extension_builder.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <windows.h>

namespace Extensions {

bool ExtensionBuilder::buildExtension(const BuildConfig& config) {
    std::string command = generateBuildCommand(config);
    std::cout << "Building extension with command: " << command << std::endl;
    return executeCommand(command);
}

std::string ExtensionBuilder::generateBuildCommand(const BuildConfig& config) {
    std::ostringstream cmd;
    
    cmd << config.compiler << " /LD";  // Build as DLL
    
    if (config.debug) {
        cmd << " /Od /Zi /MDd";  // Debug flags
    } else {
        cmd << " /O2 /MD";  // Release flags
    }
    
    // Include paths
    for (const auto& include : config.includePaths) {
        cmd << " /I\"" << include << "\"";
    }
    
    // Source files
    for (const auto& entry : std::filesystem::recursive_directory_iterator(config.projectPath)) {
        if (entry.path().extension() == ".cpp") {
            cmd << " \"" << entry.path().string() << "\"";
        }
    }
    
    // Library paths
    for (const auto& libPath : config.libraryPaths) {
        cmd << " /LIBPATH:\"" << libPath << "\"";
    }
    
    // Libraries
    for (const auto& lib : config.libraries) {
        cmd << " " << lib;
    }
    
    cmd << " /Fe:\"" << config.outputPath << "\"";
    cmd << " /link /DLL";
    
    return cmd.str();
}

bool ExtensionBuilder::executeCommand(const std::string& command) {
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    
    if (!CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return false;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exitCode == 0;
}

bool ExtensionBuilder::createTemplate(const std::string& name, const std::string& path) {
    std::filesystem::create_directories(path);
    
    // Create manifest.json
    std::ofstream manifest(path + "\\manifest.json");
    manifest << "{\n";
    manifest << "  \"id\": \"" << name << "\",\n";
    manifest << "  \"name\": \"" << name << "\",\n";
    manifest << "  \"version\": \"1.0.0\",\n";
    manifest << "  \"description\": \"Extension description\",\n";
    manifest << "  \"author\": \"Your Name\",\n";
    manifest << "  \"dependencies\": []\n";
    manifest << "}\n";
    manifest.close();
    
    // Create main.cpp
    std::ofstream main(path + "\\main.cpp");
    main << "#include \"../core/extension_manager.h\"\n";
    main << "#include <iostream>\n\n";
    main << "class " << name << "Extension : public Extensions::IExtension {\n";
    main << "public:\n";
    main << "    bool initialize() override {\n";
    main << "        std::cout << \"" << name << " extension initialized\" << std::endl;\n";
    main << "        return true;\n";
    main << "    }\n\n";
    main << "    void shutdown() override {\n";
    main << "        std::cout << \"" << name << " extension shutdown\" << std::endl;\n";
    main << "    }\n\n";
    main << "    Extensions::ExtensionInfo getInfo() const override {\n";
    main << "        return {\"" << name << "\", \"" << name << "\", \"1.0.0\", \"Extension description\", \"Your Name\", {}};\n";
    main << "    }\n";
    main << "};\n\n";
    main << "extern \"C\" __declspec(dllexport) Extensions::IExtension* createExtension() {\n";
    main << "    return new " << name << "Extension();\n";
    main << "}\n";
    main.close();
    
    return true;
}

}