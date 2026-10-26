#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <any>
#include <cstdint>
#include <mutex>

namespace kartgib::editor {

// Scripting system - supports multiple scripting languages
enum class ScriptLanguage {
    None = 0,
    Lua = 1,
    CSharp = 2,
    Python = 3
};

struct ScriptAsset {
    std::string guid;
    std::string name;
    std::string path;
    ScriptLanguage language;
    std::string sourceCode;
    uint64_t lastModified = 0;
    bool compiled = false;
    std::string compileErrors;
};

struct ScriptComponent {
    std::string scriptGuid;
    uint64_t instanceId = 0;
    bool enabled = true;
    std::unordered_map<std::string, std::any> properties;
};

struct ScriptFunction {
    std::string name;
    std::vector<std::string> parameterTypes;
    std::string returnType;
    bool isStatic = false;
    bool isPublic = true;
};

class ScriptEngine {
public:
    virtual ~ScriptEngine() = default;
    virtual ScriptLanguage getLanguage() const = 0;
    virtual bool compileScript(const std::string& source, std::string& error) = 0;
    virtual uint64_t createInstance(const std::string& className) = 0;
    virtual void destroyInstance(uint64_t instanceId) = 0;
    virtual bool callFunction(uint64_t instanceId, const std::string& functionName, 
                              const std::vector<std::any>& args, std::any& result) = 0;
    virtual void setProperty(uint64_t instanceId, const std::string& name, const std::any& value) = 0;
    virtual std::any getProperty(uint64_t instanceId, const std::string& name) = 0;
    virtual void update(float deltaTime) = 0;
};

class ScriptManager {
    std::unordered_map<std::string, std::unique_ptr<ScriptEngine>> engines_;
    std::unordered_map<std::string, ScriptAsset> scripts_;
    std::unordered_map<uint64_t, std::pair<uint64_t, ScriptEngine*>> instances_; // instanceId -> (scriptEngineId, engine*)
    uint64_t nextInstanceId_ = 1;
    std::mutex mutex_;

public:
    ScriptManager() {}
    ~ScriptEngine() {}

    bool registerEngine(std::unique_ptr<ScriptEngine> engine);
    ScriptEngine* getEngine(ScriptLanguage language);
    ScriptEngine* getEngine(const std::string& languageName);

    bool loadScript(const std::string& path, const std::string& guid);
    bool compileScript(const std::string& guid);
    
    uint64_t createInstance(const std::string& scriptGuid);
    void destroyInstance(uint64_t instanceId);
    
    bool callFunction(uint64_t instanceId, const std::string& functionName, 
                      const std::vector<std::any>& args, std::any& result);
    void setProperty(uint64_t instanceId, const std::string& name, const std::any& value);
    std::any getProperty(uint64_t instanceId, const std::string& name);

    void update(float deltaTime);

    std::vector<ScriptAsset> getAllScripts() const;
    std::optional<ScriptAsset> getScript(const std::string& guid) const;
};

// Lua scripting engine implementation
class LuaScriptEngine : public ScriptEngine {
public:
    ScriptLanguage getLanguage() const override { return ScriptLanguage::Lua; }
    bool compileScript(const std::string& source, std::string& error) override;
    uint64_t createInstance(const std::string& className) override;
    void destroyInstance(uint64_t instanceId) override;
    bool callFunction(uint64_t instanceId, const std::string& functionName,
                      const std::vector<std::any>& args, std::any& result) override;
    void setProperty(uint64_t instanceId, const std::string& name, const std::any& value) override;
    std::any getProperty(uint64_t instanceId, const std::string& name) override;
    void update(float deltaTime) override;
};

// C# scripting engine implementation (placeholder for future)
class CSharpScriptEngine : public ScriptEngine {
public:
    ScriptLanguage getLanguage() const override { return ScriptLanguage::CSharp; }
    bool compileScript(const std::string& source, std::string& error) override {
        error = "C# scripting not yet implemented";
        return false;
    }
    uint64_t createInstance(const std::string& className) override { return 0; }
    void destroyInstance(uint64_t instanceId) override {}
    bool callFunction(uint64_t instanceId, const std::string& functionName,
                      const std::vector<std::any>& args, std::any& result) override { return false; }
    void setProperty(uint64_t instanceId, const std::string& name, const std::any& value) override {}
    std::any getProperty(uint64_t instanceId, const std::string& name) override { return std::any(); }
    void update(float deltaTime) override {}
};

} // namespace kartgib::editor