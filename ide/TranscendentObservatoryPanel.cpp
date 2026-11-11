#include "ide/TranscendentObservatoryPanel.hpp"
#include "transcendent/TranscendentObservatoryEngine.hpp"
#include "transcendent/TranscendentObservatoryLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool TranscendentObservatoryPanel::s_visible = false;
bool TranscendentObservatoryPanel::s_initialized = false;
char TranscendentObservatoryPanel::s_nameBuffer[256] = {};
char TranscendentObservatoryPanel::s_typeBuffer[64] = {};
char TranscendentObservatoryPanel::s_modeBuffer[64] = {};
char TranscendentObservatoryPanel::s_sourceBuffer[128] = {};
std::vector<char> TranscendentObservatoryPanel::s_jsonBuffer(4096, '\0');
int TranscendentObservatoryPanel::s_selectedTab = 0;

void TranscendentObservatoryPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Transcendent::TranscendentObservatoryLoop::Init();
    Transcendent::TranscendentObservatoryLoop::Start();
}

void TranscendentObservatoryPanel::Shutdown() {
    if (!s_initialized) return;
    Transcendent::TranscendentObservatoryLoop::Shutdown();
    s_initialized = false;
}

void TranscendentObservatoryPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Transcendent Observatory (Layer 59)", &s_visible);
    
    const char* tabs[] = {"Telescopes", "Sensors", "Scanners", "Arrays", "Observations", "Metrics", "Report"};
    ImGui::TabBar("ObservatoryTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderTelescopeManager(); break;
        case 1: RenderSensorManager(); break;
        case 2: RenderScannerManager(); break;
        case 3: RenderArrayManager(); break;
        case 4: RenderObservations(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void TranscendentObservatoryPanel::RenderTelescopeManager() {
    ImGui::Text("Universal Telescope Management");
    ImGui::Separator();
    
    ImGui::InputText("Telescope Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Observation Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float sensitivity = 1.0f;
    static float range = 1000.0f;
    ImGui::SliderFloat("Sensitivity", &sensitivity, 0.0f, 10.0f);
    ImGui::SliderFloat("Range", &range, 0.0f, 10000.0f);
    
    if (ImGui::Button("Commission Telescope")) {
        Transcendent::TranscendentObservatoryEngine::CommissionUniversalTelescope(s_nameBuffer, s_typeBuffer, sensitivity, range);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Telescopes:");
    auto telescopes = Transcendent::TranscendentObservatoryEngine::GetAllTelescopes();
    for (const auto& telescope : telescopes) {
        ImGui::Text("%s - %s [%s] (Sens: %.2f)", telescope.telescopeId.c_str(), telescope.name.c_str(), 
                    telescope.active ? "ACTIVE" : "INACTIVE", telescope.sensitivity);
    }
}

void TranscendentObservatoryPanel::RenderSensorManager() {
    ImGui::Text("Cosmic Sensor Management");
    ImGui::Separator();
    
    ImGui::InputText("Sensor Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Sensor Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float threshold = 0.5f;
    ImGui::SliderFloat("Detection Threshold", &threshold, 0.0f, 1.0f);
    
    if (ImGui::Button("Deploy Sensor")) {
        Transcendent::TranscendentObservatoryEngine::DeployCosmicSensor(s_nameBuffer, s_typeBuffer, threshold);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Deployed Sensors:");
    auto sensors = Transcendent::TranscendentObservatoryEngine::GetAllSensors();
    for (const auto& sensor : sensors) {
        ImGui::Text("%s - %s [%s] (Acc: %.2f)", sensor.sensorId.c_str(), sensor.name.c_str(), 
                    sensor.sensorType.c_str(), sensor.accuracy);
    }
}

void TranscendentObservatoryPanel::RenderScannerManager() {
    ImGui::Text("Multiversal Scanner Management");
    ImGui::Separator();
    
    ImGui::InputText("Scanner Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Scan Mode", s_modeBuffer, sizeof(s_modeBuffer));
    
    if (ImGui::Button("Initialize Scanner")) {
        Transcendent::TranscendentObservatoryEngine::InitializeMultiversalScanner(s_nameBuffer, s_modeBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_modeBuffer, 0, sizeof(s_modeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Scanners:");
    auto scanners = Transcendent::TranscendentObservatoryEngine::GetAllScanners();
    for (const auto& scanner : scanners) {
        ImGui::Text("%s - %s [%s] (Coverage: %.1f%%)", scanner.scannerId.c_str(), scanner.name.c_str(), 
                    scanner.scanMode.c_str(), scanner.coveragePercent);
    }
}

void TranscendentObservatoryPanel::RenderArrayManager() {
    ImGui::Text("Detection Array Management");
    ImGui::Separator();
    
    ImGui::InputText("Array Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Array Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Establish Array")) {
        std::vector<std::string> sensors = {"sensor_1", "sensor_2"};
        Transcendent::TranscendentObservatoryEngine::EstablishDetectionArray(s_nameBuffer, s_typeBuffer, sensors);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Detection Arrays:");
    auto arrays = Transcendent::TranscendentObservatoryEngine::GetAllDetectionArrays();
    for (const auto& array : arrays) {
        ImGui::Text("%s - %s [%s] (Sensors: %zu)", array.arrayId.c_str(), array.name.c_str(), 
                    array.arrayType.c_str(), array.componentSensors.size());
    }
}

void TranscendentObservatoryPanel::RenderObservations() {
    ImGui::Text("Cosmic Observations");
    ImGui::Separator();
    
    ImGui::InputText("Source ID", s_sourceBuffer, sizeof(s_sourceBuffer));
    ImGui::InputText("Observation Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputTextMultiline("Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    static float confidence = 0.9f;
    ImGui::SliderFloat("Confidence", &confidence, 0.0f, 1.0f);
    
    if (ImGui::Button("Record Observation")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            Transcendent::TranscendentObservatoryEngine::RecordObservation(s_sourceBuffer, s_typeBuffer, data, confidence);
            memset(s_sourceBuffer, 0, sizeof(s_sourceBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Recent Observations:");
    auto observations = Transcendent::TranscendentObservatoryEngine::GetAllObservations();
    for (const auto& observation : observations) {
        ImGui::Text("%s - %s (Conf: %.2f)", observation.observationId.c_str(), 
                    observation.observationType.c_str(), observation.confidence);
    }
}

void TranscendentObservatoryPanel::RenderMetrics() {
    ImGui::Text("Observatory Metrics");
    ImGui::Separator();
    
    auto metrics = Transcendent::TranscendentObservatoryEngine::GetObservatoryMetrics();
    
    ImGui::Text("Telescopes: %d (%d active)", metrics["telescopeCount"].get<int>(), metrics["activeTelescopeCount"].get<int>());
    ImGui::Text("Sensors: %d", metrics["sensorCount"].get<int>());
    ImGui::Text("Scanners: %d", metrics["scannerCount"].get<int>());
    ImGui::Text("Arrays: %d", metrics["arrayCount"].get<int>());
    ImGui::Text("Observations: %d", metrics["observationCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Observation Coverage: %.4f", metrics["observationCoverage"].get<float>());
    ImGui::Text("Detection Accuracy: %.4f", metrics["detectionAccuracy"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void TranscendentObservatoryPanel::RenderReport() {
    ImGui::Text("Observatory Report");
    ImGui::Separator();
    
    auto report = Transcendent::TranscendentObservatoryEngine::GenerateObservatoryReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool TranscendentObservatoryPanel::IsVisible() {
    return s_visible;
}

void TranscendentObservatoryPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void TranscendentObservatoryPanel::Toggle() {
    s_visible = !s_visible;
}

const char* TranscendentObservatoryPanel::GetPanelName() {
    return "Transcendent Observatory";
}

const char* TranscendentObservatoryPanel::GetShortcut() {
    return "Ctrl+Shift+F31";
}

} // namespace IDE
