/**
 * @file self_patch.cpp
 * @brief SelfPatch implementation – Qt-free (C++20 / Win32)
 *
 * Adds Vulkan kernels, C++ wrappers, hot-reloads the binary,
 * and patches existing files. Uses Win32 CreateProcess for builds.
 */

#include "self_patch.hpp"
<<<<<<< HEAD
#include "process_utils.hpp"
#include <cstdio>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

// ── Constructor ──────────────────────────────────────────────────────────

SelfPatch::SelfPatch() = default;

// ── addKernel ────────────────────────────────────────────────────────────

bool SelfPatch::addKernel(const std::string& name, const std::string& templateName) {
    // Resolve paths
    std::string srcDir  = getEnvVar("RAWRXD_SRC", "src");
    std::string tplPath = srcDir + "/kernels/templates/" + templateName + ".comp";
    std::string dstPath = srcDir + "/kernels/" + name + ".comp";

    if (!fs::exists(tplPath)) {
        fprintf(stderr, "[SelfPatch] template not found: %s\n", tplPath.c_str());
        return false;
    }

    // Copy template → new kernel
    std::string tplSrc = fileutil::readAll(tplPath);
    if (tplSrc.empty()) {
        fprintf(stderr, "[SelfPatch] failed to read template: %s\n", tplPath.c_str());
        return false;
    }

    // Substitute placeholder
    const std::string placeholder = "{{KERNEL_NAME}}";
    for (size_t pos = tplSrc.find(placeholder);
         pos != std::string::npos;
         pos = tplSrc.find(placeholder, pos)) {
        tplSrc.replace(pos, placeholder.size(), name);
    }

    if (!fileutil::writeAll(dstPath, tplSrc)) {
        fprintf(stderr, "[SelfPatch] failed to write kernel: %s\n", dstPath.c_str());
        return false;
    }

    // Compile SPIR-V (glslangValidator)
    std::string spvPath = srcDir + "/kernels/" + name + ".spv";
    ProcResult pr = proc::run("glslangValidator",
                              {"-V", dstPath, "-o", spvPath}, 30000);
    if (!pr.ok()) {
        fprintf(stderr, "[SelfPatch] glslangValidator failed: %s\n", pr.stderrStr.c_str());
        return false;
    }

    fprintf(stderr, "[SelfPatch] kernel '%s' added from template '%s'\n",
            name.c_str(), templateName.c_str());
    fireKernelAdded(name);
    return true;
}

// ── addCpp ───────────────────────────────────────────────────────────────

bool SelfPatch::addCpp(const std::string& name, const std::string& deps) {
    std::string srcDir = getEnvVar("RAWRXD_SRC", "src");
    std::string hppPath = srcDir + "/kernels/" + name + "_wrapper.hpp";
    std::string cppPath = srcDir + "/kernels/" + name + "_wrapper.cpp";

    // Generate minimal header
    std::string hdr;
    hdr += "#pragma once\n";
    hdr += "// Auto-generated wrapper for kernel: " + name + "\n";
    hdr += "#include <cstdint>\n";
    if (!deps.empty()) hdr += "#include \"" + deps + "\"\n";
    hdr += "\n";
    hdr += "namespace kernels {\n";
    hdr += "bool " + name + "_dispatch(const void* input, void* output, uint32_t count);\n";
    hdr += "} // namespace kernels\n";

    // Generate minimal .cpp that loads SPIR-V and dispatches via Vulkan compute
    std::string src;
    src += "#include \"" + name + "_wrapper.hpp\"\n";
    src += "#include <cstdio>\n";
    src += "#include <cstring>\n";
    src += "#include <vector>\n\n";
    src += "#ifdef _WIN32\n";
    src += "#define WIN32_LEAN_AND_MEAN\n";
    src += "#include <windows.h>\n";
    src += "#endif\n\n";
    src += "namespace kernels {\n\n";
    src += "// Load SPIR-V binary from generated .spv file\n";
    src += "static std::vector<uint8_t> loadSpirV(const char* path) {\n";
    src += "    std::vector<uint8_t> data;\n";
    src += "    FILE* f = fopen(path, \"rb\");\n";
    src += "    if (!f) return data;\n";
    src += "    fseek(f, 0, SEEK_END);\n";
    src += "    long sz = ftell(f);\n";
    src += "    fseek(f, 0, SEEK_SET);\n";
    src += "    if (sz > 0) {\n";
    src += "        data.resize(static_cast<size_t>(sz));\n";
    src += "        fread(data.data(), 1, data.size(), f);\n";
    src += "    }\n";
    src += "    fclose(f);\n";
    src += "    return data;\n";
    src += "}\n\n";
    src += "bool " + name + "_dispatch(const void* input, void* output, uint32_t count) {\n";
    src += "    // Locate the compiled SPIR-V for this kernel\n";
    src += "    const char* spvPath = \"src/kernels/" + name + ".spv\";\n";
    src += "    auto spirv = loadSpirV(spvPath);\n";
    src += "    if (spirv.empty()) {\n";
    src += "        fprintf(stderr, \"[kernels] " + name + ": cannot load SPIR-V from %s\\n\", spvPath);\n";
    src += "        return false;\n";
    src += "    }\n\n";
    src += "    // Validate SPIR-V magic number (0x07230203)\n";
    src += "    if (spirv.size() < 4) return false;\n";
    src += "    uint32_t magic = 0;\n";
    src += "    memcpy(&magic, spirv.data(), 4);\n";
    src += "    if (magic != 0x07230203) {\n";
    src += "        fprintf(stderr, \"[kernels] " + name + ": invalid SPIR-V magic 0x%08X\\n\", magic);\n";
    src += "        return false;\n";
    src += "    }\n\n";
    src += "    // Use the Pyre compute dispatch if available, else fall back to CPU\n";
    src += "    // Try dynamic dispatch via PyreComputeEngine\n";
    src += "    typedef bool (*PyreDispatchFn)(const uint8_t*, size_t, const void*, void*, uint32_t);\n";
    src += "    static PyreDispatchFn s_pyreFn = nullptr;\n";
    src += "    static bool s_resolved = false;\n";
    src += "    if (!s_resolved) {\n";
    src += "        s_resolved = true;\n";
    src += "#ifdef _WIN32\n";
    src += "        HMODULE hMod = GetModuleHandleA(nullptr);\n";
    src += "        if (hMod) s_pyreFn = (PyreDispatchFn)GetProcAddress(hMod, \"PyreDispatchCompute\");\n";
    src += "#endif\n";
    src += "    }\n\n";
    src += "    if (s_pyreFn) {\n";
    src += "        bool ok = s_pyreFn(spirv.data(), spirv.size(), input, output, count);\n";
    src += "        if (ok) {\n";
    src += "            fprintf(stderr, \"[kernels] " + name + ": dispatched %u elements via Pyre GPU\\n\", count);\n";
    src += "            return true;\n";
    src += "        }\n";
    src += "        fprintf(stderr, \"[kernels] " + name + ": Pyre dispatch failed, falling back to CPU\\n\");\n";
    src += "    }\n\n";
    src += "    // CPU fallback: copy input to output (identity transform)\n";
    src += "    if (input && output && count > 0) {\n";
    src += "        memcpy(output, input, count);\n";
    src += "    }\n";
    src += "    fprintf(stderr, \"[kernels] " + name + ": CPU fallback for %u bytes\\n\", count);\n";
    src += "    return true;\n";
    src += "}\n\n";
    src += "} // namespace kernels\n";

    if (!fileutil::writeAll(hppPath, hdr) || !fileutil::writeAll(cppPath, src)) {
        fprintf(stderr, "[SelfPatch] failed to write C++ wrapper for '%s'\n", name.c_str());
        return false;
    }

    fprintf(stderr, "[SelfPatch] C++ wrapper '%s' generated\n", name.c_str());
    fireCppAdded(name);
    return true;
}

// ── hotReload ────────────────────────────────────────────────────────────

bool SelfPatch::hotReload() {
    fireReloadStarted();

    std::string buildDir = getEnvVar("RAWRXD_BUILD", "build");

    // CMake configure
    ProcResult cfgResult = proc::run("cmake",
        {"--build", buildDir, "--config", "Release", "--target", "RawrXD-Shell"},
        120000);

    if (!cfgResult.ok()) {
        fprintf(stderr, "[SelfPatch] hotReload build failed:\n%s\n", cfgResult.stderrStr.c_str());
        fireReloadDone(false);
        return false;
    }

    // Attempt to restart (detached)
    std::string exePath = buildDir + "/Release/RawrXD-Shell.exe";
    if (!fs::exists(exePath)) {
        exePath = buildDir + "/RawrXD-Shell.exe";
    }

    if (fs::exists(exePath)) {
        proc::startDetached(exePath, {"--hot-reload-resume"});
        fprintf(stderr, "[SelfPatch] hotReload: new binary launched\n");
    } else {
        fprintf(stderr, "[SelfPatch] hotReload: binary not found at %s, build-only\n", exePath.c_str());
    }

    fireReloadDone(true);
    return true;
}

// ── patchFile ────────────────────────────────────────────────────────────

bool SelfPatch::patchFile(const std::string& filename, const std::string& patch) {
    if (!fs::exists(filename)) {
        fprintf(stderr, "[SelfPatch] patchFile: file not found: %s\n", filename.c_str());
        return false;
    }

    // Write patch to temp file, then apply with `git apply`
    std::string tmpPatch = filename + ".patch.tmp";
    if (!fileutil::writeAll(tmpPatch, patch)) {
        fprintf(stderr, "[SelfPatch] patchFile: failed to write temp patch\n");
        return false;
    }

    ProcResult pr = proc::run("git", {"apply", "--stat", tmpPatch}, 15000);
    if (!pr.ok()) {
        // Fallback: direct string replacement if patch is a simple diff-less content
        std::string original = fileutil::readAll(filename);
        if (original.empty()) {
            fprintf(stderr, "[SelfPatch] patchFile: failed to read original: %s\n", filename.c_str());
            fs::remove(tmpPatch);
            return false;
        }
        // Append patch content (simple mode)
        original += "\n" + patch + "\n";
        if (!fileutil::writeAll(filename, original)) {
            fprintf(stderr, "[SelfPatch] patchFile: failed to write patched file\n");
            fs::remove(tmpPatch);
            return false;
        }
        fprintf(stderr, "[SelfPatch] patchFile: appended patch to %s (simple mode)\n", filename.c_str());
    } else {
        // Apply for real
        ProcResult apply = proc::run("git", {"apply", tmpPatch}, 15000);
        if (!apply.ok()) {
            fprintf(stderr, "[SelfPatch] git apply failed: %s\n", apply.stderrStr.c_str());
            fs::remove(tmpPatch);
            return false;
        }
        fprintf(stderr, "[SelfPatch] patchFile: git apply succeeded on %s\n", filename.c_str());
    }

    fs::remove(tmpPatch);
=======
#include <fstream>
#include <sstream>
#include <filesystem>
#include <windows.h>
#include <chrono>
#include <thread>
#include <cstring>

namespace fs = std::filesystem;

SelfPatch::SelfPatch() {}

bool SelfPatch::addKernel(const std::string& name, const std::string& templateName) {
    std::string tplPath = "kernels/" + templateName + ".comp";
    std::string outPath = "kernels/" + name + ".comp";
    
    // Check if already exists (idempotent)
    if (fs::exists(outPath)) {
        if (onKernelAdded) onKernelAdded(name);
        return true;
    }
    
    // Copy template
    std::error_code ec;
    fs::copy_file(tplPath, outPath, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        return false;
    }
    
    // Inject compile command into CMakeLists.txt
    std::ifstream cmakeIn("CMakeLists.txt");
    if (!cmakeIn) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << cmakeIn.rdbuf();
    std::string txt = buffer.str();
    cmakeIn.close();
    
    // Add custom command for shader compilation
    std::string cmd = "\n# Auto-generated shader compilation for " + name + "\n"
        "add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/" + name + ".comp.spv.h\n"
        "    COMMAND glslangValidator -V kernels/" + name + ".comp -o ${CMAKE_CURRENT_BINARY_DIR}/tmp_" + name + ".spv\n"
        "    COMMAND xxd -i tmp_" + name + ".spv > ${CMAKE_CURRENT_BINARY_DIR}/" + name + ".comp.spv.h\n"
        "    DEPENDS kernels/" + name + ".comp\n"
        "    COMMENT \"Building " + name + " shader\"\n"
        "    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}\n"
        ")\n"
        "add_custom_target(" + name + "_spv DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/" + name + ".comp.spv.h)\n";
    
    txt += cmd;
    
    std::ofstream cmakeOut("CMakeLists.txt");
    if (!cmakeOut) {
        return false;
    }
    cmakeOut << txt;
    cmakeOut.close();
    
    if (onKernelAdded) onKernelAdded(name);
    return true;
}

bool SelfPatch::addCpp(const std::string& name, const std::string& deps) {
    std::string hppPath = "src/gpu/" + name + ".hpp";
    std::string cppPath = "src/gpu/" + name + ".cpp";
    
    // Check if already exists
    if (fs::exists(cppPath)) {
        if (onCppAdded) onCppAdded(name);
        return true;
    }
    
    // Create directory if needed
    fs::create_directories("src/gpu");
    
    // Write header
    std::string hppContent = "#pragma once\n"
        "#include <vector>\n"
        "#include <cstddef>\n"
        "\n"
        "class " + name + " {\n"
        "public:\n"
        "    static std::vector<uint8_t> wrap(const float* src, size_t n);\n"
        "    static void initialize();\n"
        "    static void cleanup();\n"
        "};\n";
    
    std::ofstream hppFile(hppPath);
    if (!hppFile) {
        return false;
    }
    hppFile << hppContent;
    hppFile.close();
    
    // Write implementation
    std::string cppContent = "#include \"" + name + ".hpp\"\n"
        "#include <vulkan/vulkan.h>\n"
        "#include <cstring>\n"
        "\n"
        "// External shader data generated by CMake\n"
        "extern \"C\" const unsigned char " + deps + "_comp_spv[];\n"
        "extern \"C\" const unsigned int " + deps + "_comp_spv_len;\n"
        "\n"
        "static VkDevice s_device = VK_NULL_HANDLE;\n"
        "static VkShaderModule s_shader = VK_NULL_HANDLE;\n"
        "\n"
        "void " + name + "::initialize() {\n"
        "    if (s_device != VK_NULL_HANDLE) return;\n"
        "    VkApplicationInfo appInfo{};\n"
        "    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;\n"
        "    appInfo.pApplicationName = \"SelfPatchAgent\";\n"
        "    appInfo.apiVersion = VK_API_VERSION_1_0;\n"
        "    VkInstanceCreateInfo createInfo{};\n"
        "    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;\n"
        "    createInfo.pApplicationInfo = &appInfo;\n"
        "    VkInstance instance;\n"
        "    if (vkCreateInstance(&createInfo, nullptr, &instance) != VK_SUCCESS) return;\n"
        "    uint32_t deviceCount = 0;\n"
        "    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);\n"
        "    if (deviceCount == 0) return;\n"
        "    std::vector<VkPhysicalDevice> devices(deviceCount);\n"
        "    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());\n"
        "    VkPhysicalDevice physicalDevice = devices[0];\n"
        "    float queuePriority = 1.0f;\n"
        "    VkDeviceQueueCreateInfo queueCreateInfo{};\n"
        "    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;\n"
        "    queueCreateInfo.queueFamilyIndex = 0;\n"
        "    queueCreateInfo.queueCount = 1;\n"
        "    queueCreateInfo.pQueuePriorities = &queuePriority;\n"
        "    VkDeviceCreateInfo deviceCreateInfo{};\n"
        "    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;\n"
        "    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;\n"
        "    deviceCreateInfo.queueCreateInfoCount = 1;\n"
        "    if (vkCreateDevice(physicalDevice, &deviceCreateInfo, nullptr, &s_device) != VK_SUCCESS) return;\n"
        "    VkShaderModuleCreateInfo shaderInfo{};\n"
        "    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;\n"
        "    shaderInfo.codeSize = " + deps + "_comp_spv_len;\n"
        "    shaderInfo.pCode = (const uint32_t*)" + deps + "_comp_spv;\n"
        "    vkCreateShaderModule(s_device, &shaderInfo, nullptr, &s_shader);\n"
        "}\n"
        "\n"
        "void " + name + "::cleanup() {\n"
        "    if (s_shader != VK_NULL_HANDLE && s_device != VK_NULL_HANDLE) {\n"
        "        vkDestroyShaderModule(s_device, s_shader, nullptr);\n"
        "        s_shader = VK_NULL_HANDLE;\n"
        "    }\n"
        "}\n"
        "\n"
        "std::vector<uint8_t> " + name + "::wrap(const float* src, size_t n) {\n"
        "    std::vector<uint8_t> fallback(n * sizeof(float));\n"
        "    \n"
        "    // Real Vulkan compute shader dispatch\n"
        "    if (s_device == VK_NULL_HANDLE || s_shader == VK_NULL_HANDLE) {\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    // Allocate GPU buffers for input and output\n"
        "    VkBuffer inputBuffer, outputBuffer;\n"
        "    VkDeviceMemory inputMemory, outputMemory;\n"
        "    VkDeviceSize bufferSize = n * sizeof(float);\n"
        "    \n"
        "    // Create input buffer with source data\n"
        "    VkBufferCreateInfo inputBufferInfo{};\n"
        "    inputBufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;\n"
        "    inputBufferInfo.size = bufferSize;\n"
        "    inputBufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;\n"
        "    inputBufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;\n"
        "    \n"
        "    if (vkCreateBuffer(s_device, &inputBufferInfo, nullptr, &inputBuffer) != VK_SUCCESS) {\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    // Create output buffer for results\n"
        "    VkBufferCreateInfo outputBufferInfo = inputBufferInfo;\n"
        "    outputBufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;\n"
        "    \n"
        "    if (vkCreateBuffer(s_device, &outputBufferInfo, nullptr, &outputBuffer) != VK_SUCCESS) {\n"
        "        vkDestroyBuffer(s_device, inputBuffer, nullptr);\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    // Allocate device memory for buffers\n"
        "    VkMemoryRequirements memReqs;\n"
        "    vkGetBufferMemoryRequirements(s_device, inputBuffer, &memReqs);\n"
        "    \n"
        "    VkMemoryAllocateInfo allocInfo{};\n"
        "    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;\n"
        "    allocInfo.allocationSize = memReqs.size;\n"
        "    allocInfo.memoryTypeIndex = 0;\n"
        "    \n"
        "    if (vkAllocateMemory(s_device, &allocInfo, nullptr, &inputMemory) != VK_SUCCESS) {\n"
        "        vkDestroyBuffer(s_device, inputBuffer, nullptr);\n"
        "        vkDestroyBuffer(s_device, outputBuffer, nullptr);\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    if (vkAllocateMemory(s_device, &allocInfo, nullptr, &outputMemory) != VK_SUCCESS) {\n"
        "        vkFreeMemory(s_device, inputMemory, nullptr);\n"
        "        vkDestroyBuffer(s_device, inputBuffer, nullptr);\n"
        "        vkDestroyBuffer(s_device, outputBuffer, nullptr);\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    // Bind memory to buffers\n"
        "    vkBindBufferMemory(s_device, inputBuffer, inputMemory, 0);\n"
        "    vkBindBufferMemory(s_device, outputBuffer, outputMemory, 0);\n"
        "    \n"
        "    // Map and copy input data\n"
        "    void* data;\n"
        "    vkMapMemory(s_device, inputMemory, 0, bufferSize, 0, &data);\n"
        "    std::memcpy(data, src, bufferSize);\n"
        "    vkUnmapMemory(s_device, inputMemory);\n"
        "    \n"
        "    // Create compute pipeline (descriptor set layout, pipeline layout, pipeline)\n"
        "    VkDescriptorSetLayoutBinding bindings[2]{};\n"
        "    \n"
        "    bindings[0].binding = 0;\n"
        "    bindings[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;\n"
        "    bindings[0].descriptorCount = 1;\n"
        "    bindings[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;\n"
        "    \n"
        "    bindings[1].binding = 1;\n"
        "    bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;\n"
        "    bindings[1].descriptorCount = 1;\n"
        "    bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;\n"
        "    \n"
        "    VkDescriptorSetLayoutCreateInfo layoutInfo{};\n"
        "    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;\n"
        "    layoutInfo.bindingCount = 2;\n"
        "    layoutInfo.pBindings = bindings;\n"
        "    \n"
        "    VkPipelineLayout pipelineLayout;\n"
        "    vkCreatePipelineLayout(s_device, nullptr, nullptr, &pipelineLayout);\n"
        "    \n"
        "    VkComputePipelineCreateInfo pipelineInfo{};\n"
        "    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;\n"
        "    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;\n"
        "    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;\n"
        "    pipelineInfo.stage.module = s_shader;\n"
        "    pipelineInfo.stage.pName = \"main\";\n"
        "    pipelineInfo.layout = pipelineLayout;\n"
        "    \n"
        "    VkPipeline computePipeline;\n"
        "    if (vkCreateComputePipelines(s_device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &computePipeline) != VK_SUCCESS) {\n"
        "        vkDestroyBuffer(s_device, inputBuffer, nullptr);\n"
        "        vkDestroyBuffer(s_device, outputBuffer, nullptr);\n"
        "        vkFreeMemory(s_device, inputMemory, nullptr);\n"
        "        vkFreeMemory(s_device, outputMemory, nullptr);\n"
        "        std::memcpy(fallback.data(), src, n * sizeof(float));\n"
        "        return fallback;\n"
        "    }\n"
        "    \n"
        "    // Execute compute shader on command buffer\n"
        "    VkCommandPoolCreateInfo poolInfo{};\n"
        "    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;\n"
        "    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;\n"
        "    \n"
        "    VkCommandPool cmdPool;\n"
        "    vkCreateCommandPool(s_device, &poolInfo, nullptr, &cmdPool);\n"
        "    \n"
        "    VkCommandBufferAllocateInfo allocCmdInfo{};\n"
        "    allocCmdInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;\n"
        "    allocCmdInfo.commandPool = cmdPool;\n"
        "    allocCmdInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;\n"
        "    allocCmdInfo.commandBufferCount = 1;\n"
        "    \n"
        "    VkCommandBuffer cmdBuffer;\n"
        "    vkAllocateCommandBuffers(s_device, &allocCmdInfo, &cmdBuffer);\n"
        "    \n"
        "    VkCommandBufferBeginInfo beginInfo{};\n"
        "    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;\n"
        "    vkBeginCommandBuffer(cmdBuffer, &beginInfo);\n"
        "    \n"
        "    vkCmdBindPipeline(cmdBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, computePipeline);\n"
        "    \n"
        "    uint32_t workgroupSize = 256;\n"
        "    uint32_t numWorkgroups = (n + workgroupSize - 1) / workgroupSize;\n"
        "    vkCmdDispatch(cmdBuffer, numWorkgroups, 1, 1);\n"
        "    \n"
        "    VkMemoryBarrier barrier{};\n"
        "    barrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;\n"
        "    barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;\n"
        "    barrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;\n"
        "    vkCmdPipelineBarrier(cmdBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,\n"
        "                         VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0, nullptr, 0, nullptr);\n"
        "    \n"
        "    vkEndCommandBuffer(cmdBuffer);\n"
        "    \n"
        "    VkQueue computeQueue;\n"
        "    vkGetDeviceQueue(s_device, 0, 0, &computeQueue);\n"
        "    \n"
        "    VkSubmitInfo submitInfo{};\n"
        "    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;\n"
        "    submitInfo.commandBufferCount = 1;\n"
        "    submitInfo.pCommandBuffers = &cmdBuffer;\n"
        "    \n"
        "    VkFence fence;\n"
        "    VkFenceCreateInfo fenceInfo{};\n"
        "    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;\n"
        "    vkCreateFence(s_device, &fenceInfo, nullptr, &fence);\n"
        "    \n"
        "    vkQueueSubmit(computeQueue, 1, &submitInfo, fence);\n"
        "    vkWaitForFences(s_device, 1, &fence, VK_TRUE, UINT64_MAX);\n"
        "    \n"
        "    // Read back results from GPU\n"
        "    std::vector<uint8_t> result(bufferSize);\n"
        "    vkMapMemory(s_device, outputMemory, 0, bufferSize, 0, &data);\n"
        "    std::memcpy(result.data(), data, bufferSize);\n"
        "    vkUnmapMemory(s_device, outputMemory);\n"
        "    \n"
        "    // Cleanup resources\n"
        "    vkDestroyFence(s_device, fence, nullptr);\n"
        "    vkDestroyCommandPool(s_device, cmdPool, nullptr);\n"
        "    vkDestroyPipeline(s_device, computePipeline, nullptr);\n"
        "    vkDestroyPipelineLayout(s_device, pipelineLayout, nullptr);\n"
        "    vkDestroyBuffer(s_device, inputBuffer, nullptr);\n"
        "    vkDestroyBuffer(s_device, outputBuffer, nullptr);\n"
        "    vkFreeMemory(s_device, inputMemory, nullptr);\n"
        "    vkFreeMemory(s_device, outputMemory, nullptr);\n"
        "    \n"
        "    return result;\n"
        "}\n";
    
    std::ofstream cppFile(cppPath);
    if (!cppFile) {
        return false;
    }
    cppFile << cppContent;
    cppFile.close();
    
    if (onCppAdded) onCppAdded(name);
    return true;
}

static std::string execProcess(const std::string& cmd, const std::vector<std::string>& args, int timeoutMs, int& exitCode) {
    std::string cmdLine = cmd;
    for (const auto& arg : args) {
        cmdLine += " " + arg;
    }
    
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hStdoutRead, hStdoutWrite;
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        exitCode = -1;
        return "";
    }
    
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hStdoutWrite;
    si.hStdOutput = hStdoutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLinePtr = _strdup(cmdLine.c_str());
    
    if (!CreateProcessA(NULL, cmdLinePtr, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLinePtr);
        CloseHandle(hStdoutWrite);
        CloseHandle(hStdoutRead);
        exitCode = -1;
        return "";
    }
    
    free(cmdLinePtr);
    CloseHandle(hStdoutWrite);
    
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        exitCode = -1;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hStdoutRead);
        return "";
    }
    
    DWORD dwExitCode;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);
    exitCode = static_cast<int>(dwExitCode);
    
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hStdoutRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        output.append(buffer, bytesRead);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutRead);
    
    return output;
}

bool SelfPatch::hotReload() {
    if (onReloadStarted) onReloadStarted();
    
    // Step 1: Build the project
    int exitCode = 0;
    std::string buildOutput = execProcess("cmake", {"--build", "build", "--config", "Release", "--target", "RawrXD-QtShell"}, 120000, exitCode);
    
    if (exitCode != 0) {
        if (onReloadCompleted) onReloadCompleted(false);
        return false;
    }
    
    // Step 2: Spawn new process
    fs::path newBin = fs::current_path() / "build" / "bin" / "Release" / "RawrXD-QtShell.exe";
    std::string binPath = newBin.string();
    
    // Get command line args (simplified - would need GetCommandLine parsing in real impl)
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLine = _strdup(binPath.c_str());
    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLine);
        if (onReloadCompleted) onReloadCompleted(false);
        return false;
    }
    
    free(cmdLine);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Step 3: Suicide after 500ms
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (onReloadCompleted) onReloadCompleted(true);
        ExitProcess(0);
    }).detach();
    
    return true;
}

bool SelfPatch::patchFile(const std::string& filename, const std::string& patch) {
    std::ifstream file(filename);
    if (!file) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();
    
    // Simple patch application (append or replace)
    if (patch.find("APPEND:") == 0) {
        content += patch.substr(7);
    } else if (patch.find("REPLACE:") == 0) {
        // Format: REPLACE:oldText->newText
        size_t arrowPos = patch.find("->");
        if (arrowPos != std::string::npos) {
            std::string oldText = patch.substr(8, arrowPos - 8);
            std::string newText = patch.substr(arrowPos + 2);
            
            size_t pos = 0;
            while ((pos = content.find(oldText, pos)) != std::string::npos) {
                content.replace(pos, oldText.length(), newText);
                pos += newText.length();
            }
        }
    } else {
        // Default: append
        content += "\n" + patch;
    }
    
    std::ofstream outFile(filename);
    if (!outFile) {
        return false;
    }
    outFile << content;
    outFile.close();
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}
