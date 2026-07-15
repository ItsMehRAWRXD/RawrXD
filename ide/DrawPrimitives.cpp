#include "ide/DrawPrimitives.hpp"
#include <imgui.h>

void DrawPrimitives::GreenLight(const std::string& label) {
    ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "● %s", label.c_str());
}

void DrawPrimitives::YellowLight(const std::string& label) {
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.2f, 1.0f), "● %s", label.c_str());
}

void DrawPrimitives::RedLight(const std::string& label) {
    ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "● %s", label.c_str());
}
