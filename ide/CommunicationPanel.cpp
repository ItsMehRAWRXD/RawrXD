#include "ide/CommunicationPanel.hpp"
#include "ide/PanelState.hpp"
#include "communication/IntentTranslator.hpp"
#include "communication/ExplanationGenerator.hpp"
#include "communication/DialogueManager.hpp"
#include "intent/IntentModel.hpp"
#include <imgui.h>
#include <cstring>

static char inputBuffer[256] = "";

const char* CommunicationPanel::Id() { return "CommunicationPanel"; }
void CommunicationPanel::Toggle() { PanelState::Toggle(Id()); }
bool CommunicationPanel::IsWired() { return true; }
void CommunicationPanel::Init() {}

void CommunicationPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Communication & Expression");

    // Current Intent Translation
    auto intent = IntentModel::GetCurrentIntent();
    std::string intentNL = IntentTranslator::TranslateIntentToNL(intent);
    
    ImGui::Text("Current Intent:");
    ImGui::TextWrapped("%s", intentNL.c_str());
    
    ImGui::Separator();
    
    // Explanation Generation
    if (ImGui::CollapsingHeader("Generate Explanation")) {
        if (ImGui::Button("Explain Identity")) {
            std::string explanation = ExplanationGenerator::GenerateContextualExplanation({{"topic", "identity"}});
            ImGui::TextWrapped("%s", explanation.c_str());
        }
        if (ImGui::Button("Explain Intent")) {
            std::string explanation = ExplanationGenerator::GenerateContextualExplanation({{"topic", "intent"}});
            ImGui::TextWrapped("%s", explanation.c_str());
        }
    }
    
    ImGui::Separator();
    
    // Dialogue Interface
    ImGui::Text("Dialogue:");
    
    // Input field
    ImGui::InputText("##input", inputBuffer, sizeof(inputBuffer));
    ImGui::SameLine();
    
    if (ImGui::Button("Send")) {
        if (strlen(inputBuffer) > 0) {
            auto processed = DialogueManager::ProcessInput(inputBuffer);
            std::string response = DialogueManager::GenerateResponse(processed);
            // In a real implementation, this would display the conversation
            inputBuffer[0] = '\0'; // Clear input
        }
    }
    
    // Conversation history
    if (ImGui::CollapsingHeader("Conversation History")) {
        auto history = DialogueManager::GetConversationHistory();
        ImGui::BeginChild("conv_history", ImVec2(0, 150), true);
        for (const auto& turn : history) {
            ImGui::Text("User: %s", turn.value("input", "").c_str());
            ImGui::Text("System: %s", turn.value("response", "").c_str());
            ImGui::Separator();
        }
        ImGui::EndChild();
        
        if (ImGui::Button("Reset Conversation")) {
            DialogueManager::ResetConversation();
        }
    }
    
    // Explanation History
    if (ImGui::CollapsingHeader("Explanation History")) {
        auto expHistory = ExplanationGenerator::GetExplanationHistory();
        ImGui::BeginChild("exp_history", ImVec2(0, 100), true);
        int count = 0;
        for (const auto& exp : expHistory) {
            if (count++ > 5) break;
            ImGui::Text("[%s] %s", 
                exp.value("type", "unknown").c_str(),
                exp.value("explanation", "").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
