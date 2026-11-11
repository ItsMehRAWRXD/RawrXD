#include "vulkan_renderer.hpp"
#include "forensics_png.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>
static int gValidationMessages = 0;
void VulkanRenderer::noteValidationMessage() { gValidationMessages++; }
int VulkanRenderer::validationCount() const { return gValidationMessages; }
void VulkanRenderer::armForensics() {
    forensicsArmed_ = true;
    forensicsStep_ = 0;
    forensicsWarmup_ = 0;
    debugTriangleMode_ = false;
    std::cout << "[FORENSICS] armed steps=sky,terrain,combined" << std::endl;
}

void VulkanRenderer::prepareForensics() {
    lightDiag_ = 0.0f;
    if (g04Sample_ && !forensicsArmed_ && g04SampleFrame_ == 2) readbackThisFrame_ = true;
    if (g04Sample_ && !forensicsArmed_) g04SampleFrame_++;
    if (!forensicsArmed_ || forensicsStep_ < 0 || forensicsStep_ > 4) return;
    if (forensicsWarmup_ < 2) { forensicsWarmup_++; return; }
    configureForensicsPass();
}

static const char* stageName(bool pass, bool failed, const char* fail) {
    if (failed) return fail;
    if (pass) return "PASS";
    return "UNKNOWN";
}

void VulkanRenderer::noteForensicsReadback(uint64_t nonClear, uint64_t uniqueColors,
    const uint8_t* pixels, bool bgra) {
    if (!forensicsArmed_) return;
    if (forensicsStep_ == 0) { skyNonClear_ = nonClear; skyUnique_ = uniqueColors; }
    if (forensicsStep_ == 1) { terrainNonClear_ = nonClear; terrainUnique_ = uniqueColors; }
    if (forensicsStep_ == 4) { combinedNonClear_ = nonClear; combinedUnique_ = uniqueColors; }
    retainForensicsFrame(pixels, bgra);
    std::cout << "[G04_PIXEL] label=" << g04Label_ << " width=" << g04Width_
              << " height=" << g04Height_ << " format=" << static_cast<int>(swapchainImageFormat_)
              << " readback=PASS non_clear_pixels=" << nonClear
              << " unique_colors=" << uniqueColors << std::endl;
    if (forensicsStep_ < 4) { forensicsStep_++; return; }
    publishG05Evidence(pixels, bgra);
    const uint64_t pixelsN = static_cast<uint64_t>(g04Width_) * g04Height_;
    const bool skyOk = skyNonClear_ > pixelsN / 2;
    const bool terrainOk = terrainNonClear_ > pixelsN / 10 && terrainNonClear_ < pixelsN * 9 / 10;
    const bool visible = skyOk && terrainOk && combinedNonClear_ > pixelsN / 2;
    const bool shaderOk = atmospherePipeline_ != VK_NULL_HANDLE && graphicsPipeline_ != VK_NULL_HANDLE;
    const bool meshOk = lastIndexCount_ > 0;
    const char* shader = stageName(shaderOk, !shaderOk, "SHADER_LOAD_FAILED");
    const char* pipeline = stageName(shaderOk, !shaderOk, "PIPELINE_INVALID");
    const char* mesh = stageName(meshOk, !meshOk, "GEOMETRY_MISSING");
    const char* camera = stageName(!geometryOutsideFrustum_, geometryOutsideFrustum_, "GEOMETRY_OUTSIDE_FRUSTUM");
    const char* uniforms = stageName(!uniformBindingInvalid_, uniformBindingInvalid_, "UNIFORM_BINDING_INVALID");
    const char* depth = stageName(terrainNonClear_ > 1000, false, "DEPTH_REJECTED");
    const char* raster = stageName(terrainNonClear_ > 1000, false, "PRIMITIVES_CULLED");
    const bool colorOk = swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_SRGB
        || swapchainImageFormat_ == VK_FORMAT_B8G8R8A8_UNORM
        || swapchainImageFormat_ == VK_FORMAT_R8G8B8A8_SRGB
        || swapchainImageFormat_ == VK_FORMAT_R8G8B8A8_UNORM;
    const char* color = stageName(colorOk, !colorOk, "COLOR_OUTPUT_INVALID");
    const char* fb = visible ? "PASS" : "NO_VISIBLE_PIXELS";
    const char* present = stageName(presentSuccess_ > 0, presentSuccess_ == 0 && presentFail_ > 0, "PRESENT_FAILED");
    const char* validation = enableValidation_ ? "MEASURED" : "UNKNOWN";
    const char* names[] = {"shader","pipeline","mesh","camera","uniforms","depth","rasterizer","color","framebuffer","present"};
    const char* values[] = {shader,pipeline,mesh,camera,uniforms,depth,raster,color,fb,present};
    const char* first = "NONE";
    for (int i = 0; i < 10; ++i) {
        if (std::string(values[i]) != "PASS") { first = names[i]; break; }
    }
    wchar_t modulePath[32768] = {};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    auto pngPath = evidence / "kartgib_frame_006.png";
    auto jsonPath = evidence / "kartgib_render_visibility_006.json";
    writeStoredPng(pngPath, pixels, g04Width_, g04Height_, bgra);
    std::ofstream json(jsonPath);
    json << "{\"gate\":\"KARTGIB_RENDER_VISIBILITY_FORENSICS_006\",\"device\":\"" << deviceName_
         << "\",\"validation\":\"" << validation << "\",\"validation_messages\":" << validationCount()
         << ",\"atmosphere_submits\":" << atmosphereSubmits_ << ",\"terrain_submits\":" << terrainSubmits_
         << ",\"present_success\":" << presentSuccess_ << ",\"present_fail\":" << presentFail_
         << ",\"sky_non_clear\":" << skyNonClear_ << ",\"terrain_non_clear\":" << terrainNonClear_
         << ",\"combined_non_clear\":" << combinedNonClear_ << ",\"combined_unique_colors\":" << combinedUnique_
         << ",\"first_failed_or_unverified\":\"" << first << "\",\"visible_output\":\""
         << (visible ? "PASS" : "FAIL") << "\",\"image\":\"evidence/kartgib_frame_006.png\"}\n";
    std::cout << "KartGib - Render Diagnostics " << (visible ? "VISIBILITY PASS" : "VISIBILITY FAIL")
              << " device=" << deviceName_ << " present=" << presentSuccess_ << "/"
              << (presentSuccess_ + presentFail_) << " atmosphere=" << atmosphereSubmits_
              << " terrain=" << terrainSubmits_ << " non_clear=" << combinedNonClear_
              << " first=" << first << " [G04_PIXEL] visible_output="
              << (visible ? "PASS" : "FAIL") << std::endl;
    forensicsArmed_ = false;
    forensicsStep_ = -1;
}
