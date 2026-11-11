#include "editor/scripting.hpp"

namespace kartgib::editor {

bool ScriptManager::registerEngine(std::unique_ptr<ScriptEngine> engine) {
    if (!engine) return false;
    ScriptLanguage lang = engine->getLanguage();
    engines_[std::to_string(static_cast<int>(lang))] = std::move(engine);
    return true;
}

ScriptEngine* ScriptManager::getEngine(ScriptLanguage language) {
    auto it = engines_.find(std::to_string(static_cast<int>(language)));
    return it != engines_.end() ? it->second.get() : nullptr;
}

ScriptEngine* ScriptManager::getEngine(const std::string& languageName) {
    for (auto& [langName, engine] : engines_) {
        if (langName == languageName) return engine.get();
    }
    return nullptr;
}

bool ScriptManager::loadScript(const std::string& path, const std::string& guid) {
    ScriptAsset asset;
    asset.guid = guid;
    asset.name = std::filesystem::path(path).filename().string();
    asset.path = path;
    
    std::string ext = std::filesystem::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == ".lua") asset.language = ScriptLanguage::Lua;
    else if (ext == ".cs") asset.language = ScriptLanguage::CSharp;
    else if (ext == ".py") asset.language = ScriptLanguage::Python;
    else return false;
    
    // Read source code
    std::ifstream file(path);
    if (!file.is_open()) return false;
    std::stringstream buffer;
    buffer << file.rdbuf();
    asset.sourceCode = buffer.str();
    file.close();
    
    scripts_[guid] = asset;
    return compileScript(guid);
}

bool ScriptManager::compileScript(const std::string& guid) {
    auto it = scripts_.find(guid);
    if (it == scripts_.end()) return false;
    
    ScriptEngine* engine = getEngine(it->second.language);
    if (!engine) return false;
    
    std::string error;
    bool success = engine->compileScript(it->second.sourceCode, error);
    it->second.compiled = success;
    it->second.compileErrors = error;
    return success;
}

uint64_t ScriptManager::createInstance(const std::string& scriptGuid) {
    auto it = scripts_.find(scriptGuid);
    if (it == scripts_.end() || !it->second.compiled) return 0;
    
    ScriptEngine* engine = getEngine(it->second.language);
    if (!engine) return 0;
    
    uint64_t instanceId = nextInstanceId_++;
    instances_[instanceId] = {nextInstanceId_ - 1, engine};
    
    uint64_t internalId = engine->createInstance("Main");
    instances_[instanceId].first = internalId;
    
    return instanceId;
}

void ScriptManager::destroyInstance(uint64_t instanceId) {
    auto it = instances_.find(instanceId);
    if (it != instances_.end()) {
        it->second.second->destroyInstance(it->second.first);
        instances_.erase(it);
    }
}

bool ScriptManager::callFunction(uint64_t instanceId, const std::string& functionName,
                                 const std::vector<std::any>& args, std::any& result) {
    auto it = instances_.find(instanceId);
    if (it == instances_.end()) return false;
    return it->second.second->callFunction(it->second.first, functionName, args, result);
}

void ScriptManager::setProperty(uint64_t instanceId, const std::string& name, const std::any& value) {
    auto it = instances_.find(instanceId);
    if (it != instances_.end()) {
        it->second.second->setProperty(it->second.first, name, value);
    }
}

std::any ScriptManager::getProperty(uint64_t instanceId, const std::string& name) {
    auto it = instances_.find(instanceId);
    if (it != instances_.end()) {
        return it->second.second->getProperty(it->second.first, name);
    }
    return std::any();
}

void ScriptManager::update(float deltaTime) {
    for (auto& [instanceId, info] : instances_) {
        info.second->update(deltaTime);
    }
}

std::vector<ScriptAsset> ScriptManager::getAllScripts() const {
    std::vector<ScriptAsset> result;
    for (const auto& [guid, asset] : scripts_) {
        result.push_back(asset);
    }
    return result;
}

std::optional<ScriptAsset> ScriptManager::getScript(const std::string& guid) const {
    auto it = scripts_.find(guid);
    if (it != scripts_.end()) return it->second;
    return std::nullopt;
}

bool LuaScriptEngine::compileScript(const std::string& source, std::string& error) {
    // Lua compilation would go here - using LuaJIT or lua 5.4
    // For now, just mark as compiled
    error.clear();
    return true;
}

uint64_t LuaScriptEngine::createInstance(const std::string& className) {
    // Create Lua instance
    return 0;
}

void LuaScriptEngine::destroyInstance(uint64_t instanceId) {
    // Destroy Lua instance
}

bool LuaScriptEngine::callFunction(uint64_t instanceId, const std::string& functionName,
                                   const std::vector<std::any>& args, std::any& result) {
    // Call Lua function
    return false;
}

void LuaScriptEngine::setProperty(uint64_t instanceId, const std::string& name, const std::any& value) {
    // Set Lua property
}

std::any LuaScriptEngine::getProperty(uint64_t instanceId, const std::string& name) {
    // Get Lua property
    return std::any();
}

void LuaScriptEngine::update(float deltaTime) {
    // Update Lua scripts
}

} // namespace kartgib::editor