#include "ide/MetaversalArchivePanel.hpp"
#include "metaversal/MetaversalArchiveEngine.hpp"
#include "metaversal/MetaversalArchiveLoop.hpp"
#include <imgui.h>
#include <string>

namespace IDE {

bool MetaversalArchivePanel::s_visible = false;
bool MetaversalArchivePanel::s_initialized = false;
char MetaversalArchivePanel::s_nameBuffer[256] = {};
char MetaversalArchivePanel::s_descriptionBuffer[512] = {};
char MetaversalArchivePanel::s_universeBuffer[128] = {};
char MetaversalArchivePanel::s_typeBuffer[64] = {};
char MetaversalArchivePanel::s_authorBuffer[128] = {};
char MetaversalArchivePanel::s_classificationBuffer[64] = {};
std::vector<char> MetaversalArchivePanel::s_jsonBuffer(4096, '\0');
int MetaversalArchivePanel::s_selectedTab = 0;

void MetaversalArchivePanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Metaversal::MetaversalArchiveLoop::Init();
    Metaversal::MetaversalArchiveLoop::Start();
}

void MetaversalArchivePanel::Shutdown() {
    if (!s_initialized) return;
    Metaversal::MetaversalArchiveLoop::Shutdown();
    s_initialized = false;
}

void MetaversalArchivePanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Metaversal Archive (Layer 58)", &s_visible);
    
    const char* tabs[] = {"Histories", "Records", "Libraries", "Documents", "Indices", "Metrics", "Report"};
    ImGui::TabBar("ArchiveTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderHistoryManager(); break;
        case 1: RenderRecordManager(); break;
        case 2: RenderLibraryManager(); break;
        case 3: RenderDocumentManager(); break;
        case 4: RenderIndexManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void MetaversalArchivePanel::RenderHistoryManager() {
    ImGui::Text("Universal History Management");
    ImGui::Separator();
    
    ImGui::InputText("History Title", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Description", s_descriptionBuffer, sizeof(s_descriptionBuffer));
    ImGui::InputText("Universe ID", s_universeBuffer, sizeof(s_universeBuffer));
    ImGui::InputTextMultiline("Timeline (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Record History")) {
        nlohmann::json timeline = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!timeline.is_discarded()) {
            Metaversal::MetaversalArchiveEngine::RecordUniversalHistory(s_nameBuffer, s_descriptionBuffer, s_universeBuffer, timeline);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_descriptionBuffer, 0, sizeof(s_descriptionBuffer));
            memset(s_universeBuffer, 0, sizeof(s_universeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Recorded Histories:");
    auto histories = Metaversal::MetaversalArchiveEngine::GetAllHistories();
    for (const auto& history : histories) {
        ImGui::Text("%s - %s (Universe: %s)", history.historyId.c_str(), history.title.c_str(), history.universeId.c_str());
    }
}

void MetaversalArchivePanel::RenderRecordManager() {
    ImGui::Text("Cosmic Record Management");
    ImGui::Separator();
    
    ImGui::InputText("Record Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Record Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputTextMultiline("Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Archive Record")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            std::vector<std::string> tags = {"cosmic", "archive"};
            Metaversal::MetaversalArchiveEngine::ArchiveCosmicRecord(s_nameBuffer, s_typeBuffer, data, tags);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Archived Records:");
    auto records = Metaversal::MetaversalArchiveEngine::GetAllRecords();
    for (const auto& record : records) {
        ImGui::Text("%s - %s [%s]", record.recordId.c_str(), record.name.c_str(), record.recordType.c_str());
    }
}

void MetaversalArchivePanel::RenderLibraryManager() {
    ImGui::Text("Multiversal Library Management");
    ImGui::Separator();
    
    ImGui::InputText("Library Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Description", s_descriptionBuffer, sizeof(s_descriptionBuffer));
    
    if (ImGui::Button("Establish Library")) {
        std::vector<std::string> universes = {"universe_1", "universe_2"};
        Metaversal::MetaversalArchiveEngine::EstablishMultiversalLibrary(s_nameBuffer, s_descriptionBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_descriptionBuffer, 0, sizeof(s_descriptionBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Libraries:");
    auto libraries = Metaversal::MetaversalArchiveEngine::GetAllLibraries();
    for (const auto& library : libraries) {
        ImGui::Text("%s - %s (Universes: %zu)", library.libraryId.c_str(), library.name.c_str(), library.universesServed.size());
    }
}

void MetaversalArchivePanel::RenderDocumentManager() {
    ImGui::Text("Omniversal Document Management");
    ImGui::Separator();
    
    ImGui::InputText("Document Title", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Author", s_authorBuffer, sizeof(s_authorBuffer));
    ImGui::InputText("Classification", s_classificationBuffer, sizeof(s_classificationBuffer));
    ImGui::InputTextMultiline("Content (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Create Document")) {
        nlohmann::json content = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!content.is_discarded()) {
            std::vector<std::string> universes = {"universe_1"};
            Metaversal::MetaversalArchiveEngine::CreateOmniversalDocument(s_nameBuffer, s_authorBuffer, s_classificationBuffer, content, universes);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_authorBuffer, 0, sizeof(s_authorBuffer));
            memset(s_classificationBuffer, 0, sizeof(s_classificationBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Omniversal Documents:");
    auto documents = Metaversal::MetaversalArchiveEngine::GetAllDocuments();
    for (const auto& document : documents) {
        ImGui::Text("%s - %s [%s] by %s", document.documentId.c_str(), document.title.c_str(), 
                    document.classification.c_str(), document.author.c_str());
    }
}

void MetaversalArchivePanel::RenderIndexManager() {
    ImGui::Text("Archive Index Management");
    ImGui::Separator();
    
    ImGui::InputText("Index Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Index Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Create Index")) {
        Metaversal::MetaversalArchiveEngine::CreateArchiveIndex(s_nameBuffer, s_typeBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Archive Indices:");
    auto indices = Metaversal::MetaversalArchiveEngine::GetAllIndices();
    for (const auto& index : indices) {
        ImGui::Text("%s - %s [%s] (Entries: %zu)", index.indexId.c_str(), index.name.c_str(), 
                    index.indexType.c_str(), index.entries.size());
    }
}

void MetaversalArchivePanel::RenderMetrics() {
    ImGui::Text("Archive Metrics");
    ImGui::Separator();
    
    auto metrics = Metaversal::MetaversalArchiveEngine::GetArchiveMetrics();
    
    ImGui::Text("Histories: %d", metrics["historyCount"].get<int>());
    ImGui::Text("Records: %d", metrics["recordCount"].get<int>());
    ImGui::Text("Libraries: %d", metrics["libraryCount"].get<int>());
    ImGui::Text("Documents: %d", metrics["documentCount"].get<int>());
    ImGui::Text("Indices: %d", metrics["indexCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Archive Completeness: %.4f", metrics["archiveCompleteness"].get<float>());
    ImGui::Text("Preservation Index: %.4f", metrics["preservationIndex"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void MetaversalArchivePanel::RenderReport() {
    ImGui::Text("Archive Report");
    ImGui::Separator();
    
    auto report = Metaversal::MetaversalArchiveEngine::GenerateArchiveReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool MetaversalArchivePanel::IsVisible() {
    return s_visible;
}

void MetaversalArchivePanel::SetVisible(bool visible) {
    s_visible = visible;
}

void MetaversalArchivePanel::Toggle() {
    s_visible = !s_visible;
}

const char* MetaversalArchivePanel::GetPanelName() {
    return "Metaversal Archive";
}

const char* MetaversalArchivePanel::GetShortcut() {
    return "Ctrl+Shift+F30";
}

} // namespace IDE
