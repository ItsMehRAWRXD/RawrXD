#include "agentic_chat.h"
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

namespace RawrXD {

// AgenticChat Implementation

AgenticChat::AgenticChat(const std::string& chat_id)
    : chat_id_(chat_id), title_("New Chat"), current_mode_(AgentMode::AGENT),
      current_model_("auto"), auto_model_(true), is_busy_(false) {
    
    // Default agent configuration
    agent_config_.name = "Default Agent";
    agent_config_.system_prompt = "You are a helpful AI assistant integrated into an IDE.";
    agent_config_.model_name = "auto";
    agent_config_.temperature = 0.7f;
    agent_config_.max_tokens = 2048;
    agent_config_.auto_execute = false;
    agent_config_.allowed_tools = {"file_read", "file_write", "terminal", "search"};
}

AgenticChat::~AgenticChat() = default;

void AgenticChat::SendMessage(const std::string& content) {
    ChatMessage msg;
    msg.role = "user";
    msg.content = content;
    msg.timestamp = FormatTimestamp();
    msg.agent_mode = GetModeString();
    msg.model_name = current_model_;
    messages_.push_back(msg);
}

void AgenticChat::ReceiveResponse(const std::string& response) {
    ChatMessage msg;
    msg.role = "assistant";
    msg.content = response;
    msg.timestamp = FormatTimestamp();
    msg.agent_mode = GetModeString();
    msg.model_name = current_model_;
    messages_.push_back(msg);
}

void AgenticChat::ClearHistory() {
    messages_.clear();
}

void AgenticChat::SetMode(AgentMode mode) {
    current_mode_ = mode;
}

std::string AgenticChat::GetModeString() const {
    switch (current_mode_) {
        case AgentMode::AGENT: return "Agent";
        case AgentMode::PLAN: return "Plan";
        case AgentMode::ASK: return "Ask";
        case AgentMode::EDIT: return "Edit";
        case AgentMode::CONFIGURE: return "Configure";
        default: return "Unknown";
    }
}

void AgenticChat::SetModel(const std::string& model_name) {
    current_model_ = model_name;
    if (model_name != "auto") {
        auto_model_ = false;
    }
}

void AgenticChat::SetAgentConfig(const AgentConfig& config) {
    agent_config_ = config;
}

std::string AgenticChat::FormatTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// ChatManager Implementation

ChatManager::ChatManager() : next_chat_number_(1) {
    // Add default model directories
    model_directories_.push_back("D:\\OllamaModels");
    model_directories_.push_back("C:\\Users\\HiH8e\\OneDrive\\Desktop\\Powershield\\models");
    
    ScanModelDirectories();
}

ChatManager::~ChatManager() = default;

std::string ChatManager::CreateNewChat() {
    std::string chat_id = GenerateChatId();
    auto chat = std::make_shared<AgenticChat>(chat_id);
    chat->SetTitle("Chat " + std::to_string(next_chat_number_++));
    chats_[chat_id] = chat;
    active_chat_id_ = chat_id;
    return chat_id;
}

bool ChatManager::DeleteChat(const std::string& chat_id) {
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        chats_.erase(it);
        if (active_chat_id_ == chat_id) {
            active_chat_id_.clear();
            if (!chats_.empty()) {
                active_chat_id_ = chats_.begin()->first;
            }
        }
        return true;
    }
    return false;
}

std::shared_ptr<AgenticChat> ChatManager::GetChat(const std::string& chat_id) {
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> ChatManager::GetAllChatIds() {
    std::vector<std::string> ids;
    for (const auto& [id, chat] : chats_) {
        ids.push_back(id);
    }
    return ids;
}

void ChatManager::SetActiveChat(const std::string& chat_id) {
    if (chats_.find(chat_id) != chats_.end()) {
        active_chat_id_ = chat_id;
    }
}

std::shared_ptr<AgenticChat> ChatManager::GetActiveChat() {
    return GetChat(active_chat_id_);
}

void ChatManager::AddModelDirectory(const std::string& path) {
    if (std::find(model_directories_.begin(), model_directories_.end(), path) == model_directories_.end()) {
        model_directories_.push_back(path);
        ScanModelDirectories();
    }
}

void ChatManager::RemoveModelDirectory(const std::string& path) {
    auto it = std::find(model_directories_.begin(), model_directories_.end(), path);
    if (it != model_directories_.end()) {
        model_directories_.erase(it);
        ScanModelDirectories();
    }
}

void ChatManager::ScanModelDirectories() {
    available_models_.clear();
    
    for (const auto& dir : model_directories_) {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            ScanDirectory(dir);
        }
    }
    
    // Sort models by name
    std::sort(available_models_.begin(), available_models_.end(),
        [](const ModelInfo& a, const ModelInfo& b) {
            return a.name < b.name;
        });
}

void ChatManager::ScanDirectory(const std::string& dir) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                
                if (ext == ".gguf" || ext == ".bin" || ext == ".safetensors") {
                    ModelInfo info;
                    info.name = entry.path().stem().string();
                    info.path = entry.path().string();
                    info.type = ext.substr(1); // Remove dot
                    info.size_bytes = fs::file_size(entry);
                    info.is_loaded = false;
                    available_models_.push_back(info);
                }
            }
        }
    } catch (const std::exception& e) {
        // Silently handle errors
    }
}

bool ChatManager::LoadModel(const std::string& model_name) {
    // Find model
    for (auto& model : available_models_) {
        if (model.name == model_name) {
            // Unload previous model
            if (!loaded_model_name_.empty()) {
                UnloadModel(loaded_model_name_);
            }
            
            // Load new model (scalar)
            model.is_loaded = true;
            loaded_model_name_ = model_name;
            return true;
        }
    }
    return false;
}

bool ChatManager::UnloadModel(const std::string& model_name) {
    for (auto& model : available_models_) {
        if (model.name == model_name) {
            model.is_loaded = false;
            if (loaded_model_name_ == model_name) {
                loaded_model_name_.clear();
            }
            return true;
        }
    }
    return false;
}

ModelInfo* ChatManager::GetLoadedModel() {
    if (loaded_model_name_.empty()) return nullptr;
    
    for (auto& model : available_models_) {
        if (model.name == loaded_model_name_ && model.is_loaded) {
            return &model;
        }
    }
    return nullptr;
}

std::string ChatManager::GenerateChatId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return "chat_" + std::to_string(ms.count());
}

} // namespace RawrXD
