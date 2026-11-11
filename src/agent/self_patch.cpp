#include "self_patch.hpp"
#include "snapshot/ISnapshotEngine.hpp"
#include "snapshot/SnapshotEngineAdapter.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>

SelfPatch::SelfPatch() = default;
SelfPatch::~SelfPatch() = default;

void SelfPatch::setSnapshotEngine(std::unique_ptr<ISnapshotEngine> engine) {
    m_snapshotEngine = std::move(engine);
}

static bool capturePreWrite(ISnapshotEngine* engine, const std::string& filePath) {
    if (!engine) return true;
    return engine->capturePreWrite(filePath);
}

bool SelfPatch::addKernel(const std::string& name, const std::string& templateName) {
    std::string tplPath = "kernels/" + templateName + ".comp";
    std::string outPath = "kernels/" + name + ".comp";

    // Snapshot: capture files before modification
    if (m_snapshotEngine) {
        m_snapshotEngine->capturePreWrite(outPath);
        m_snapshotEngine->capturePreWrite("CMakeLists.txt");
    }

    // Check if already exists (idempotent)
    if (std::filesystem::exists(outPath)) {
        std::cout << "Kernel " << name << " already exists\n";
        return true;
    }

    // Copy template
    {
        std::ifstream src(tplPath, std::ios::binary);
        if (!src) {
            std::cerr << "Failed to open template: " << tplPath << "\n";
            return false;
        }
        std::ofstream dst(outPath, std::ios::binary);
        if (!dst) {
            std::cerr << "Failed to create: " << outPath << "\n";
            return false;
        }
        dst << src.rdbuf();
    }

    // Inject compile command into CMakeLists.txt
    {
        std::ifstream cmake("CMakeLists.txt");
        if (!cmake) {
            std::cerr << "Failed to open CMakeLists.txt\n";
            return false;
        }
        std::string txt((std::istreambuf_iterator<char>(cmake)), std::istreambuf_iterator<char>());

        std::string cmd = R"(
# Auto-generated shader compilation for )" + name + R"(
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/)" + name + R"(.comp.spv.h
    COMMAND glslangValidator -V kernels/)" + name + R"(.comp -o ${CMAKE_CURRENT_BINARY_DIR}/tmp_)" + name + R"(.spv
    COMMAND xxd -i tmp_)" + name + R"(.spv > ${CMAKE_CURRENT_BINARY_DIR}/)" + name + R"(.comp.spv.h
    DEPENDS kernels/)" + name + R"(.comp
    COMMENT "Building )" + name + R"(" shader
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target()" + name + R"(_spv DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/)" + name + R"(.comp.spv.h)
)";

        txt += "\n" + cmd;

        std::ofstream out("CMakeLists.txt", std::ios::binary);
        if (!out) {
            std::cerr << "Failed to write CMakeLists.txt\n";
            return false;
        }
        out << txt;
    }

    std::cout << "Added kernel " << name << "\n";
    return true;
}

bool SelfPatch::addCpp(const std::string& name, const std::string& deps) {
    std::string hppPath = "src/gpu/" + name + ".hpp";
    std::string cppPath = "src/gpu/" + name + ".cpp";

    // Snapshot: capture files before modification
    if (m_snapshotEngine) {
        m_snapshotEngine->capturePreWrite(hppPath);
        m_snapshotEngine->capturePreWrite(cppPath);
    }

    // Check if already exists
    if (std::filesystem::exists(cppPath)) {
        std::cout << "C++ file " << name << " already exists\n";
        return true;
    }

    // Create directory if needed
    std::filesystem::create_directories("src/gpu");

    // Write header
    {
        std::ofstream hppFile(hppPath);
        if (!hppFile) {
            std::cerr << "Failed to create " << hppPath << "\n";
            return false;
        }
        hppFile << "#pragma once\n"
                << "#include <QByteArray>\n"
                << "#include <cstddef>\n\n"
                << "class " << name << " {\n"
                << "public:\n"
                << "    static QByteArray wrap(const float* src, size_t n);\n"
                << "    static void initialize();\n"
                << "    static void cleanup();\n"
                << "};\n";
    }

    // Write implementation
    {
        std::ofstream cppFile(cppPath);
        if (!cppFile) {
            std::cerr << "Failed to create " << cppPath << "\n";
            return false;
        }
        cppFile << "#include \"" << name << ".hpp\"\n"
                << "#include <vulkan/vulkan.h>\n"
                << "#include <QDebug>\n\n"
                << "extern \"C\" const unsigned char " << name << "_comp_spv[];\n"
                << "extern \"C\" const unsigned int " << name << "_comp_spv_len;\n\n"
                << "static VkDevice s_device = VK_NULL_HANDLE;\n"
                << "static VkShaderModule s_shader = VK_NULL_HANDLE;\n\n"
                << "void " << name << "::initialize() {\n"
                << "    // TODO: Initialize Vulkan resources\n"
                << "}\n\n"
                << "void " << name << "::cleanup() {\n"
                << "    if (s_shader != VK_NULL_HANDLE && s_device != VK_NULL_HANDLE) {\n"
                << "        vkDestroyShaderModule(s_device, s_shader, nullptr);\n"
                << "        s_shader = VK_NULL_HANDLE;\n"
                << "    }\n"
                << "}\n\n"
                << "QByteArray " << name << "::wrap(const float* src, size_t n) {\n"
                << "    if (s_device == VK_NULL_HANDLE || s_shader == VK_NULL_HANDLE) {\n"
                << "        QByteArray fallback(n * sizeof(float), 0);\n"
                << "        memcpy(fallback.data(), src, n * sizeof(float));\n"
                << "        return fallback;\n"
                << "    }\n"
                << "    return QByteArray();\n"
                << "}\n";
    }

    std::cout << "Added C++ file " << name << "\n";
    return true;
}

bool SelfPatch::patchFile(const std::string& filename, const std::string& patch) {
    // Snapshot: capture file before modification
    if (m_snapshotEngine) {
        m_snapshotEngine->capturePreWrite(filename);
    }

    std::ifstream in(filename);
    if (!in) {
        std::cerr << "Failed to open file for patching: " << filename << "\n";
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Simple patch application (append or replace)
    if (patch.rfind("APPEND:", 0) == 0) {
        content += patch.substr(7);
    } else if (patch.rfind("REPLACE:", 0) == 0) {
        std::string rest = patch.substr(8);
        size_t arrow = rest.find("->");
        if (arrow != std::string::npos) {
            std::string oldText = rest.substr(0, arrow);
            std::string newText = rest.substr(arrow + 2);
            size_t pos = content.find(oldText);
            if (pos != std::string::npos) {
                content.replace(pos, oldText.size(), newText);
            } else {
                std::cerr << "Old text not found in file: " << oldText << "\n";
                return false;
            }
        } else {
            std::cerr << "Invalid REPLACE patch format\n";
            return false;
        }
    } else {
        std::cerr << "Unknown patch format\n";
        return false;
    }

    std::ofstream out(filename, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::cerr << "Failed to write patched file: " << filename << "\n";
        return false;
    }
    out << content;

    std::cout << "Patched file: " << filename << "\n";
    return true;
}
