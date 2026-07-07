#ifndef MODEL_ROUTER_ADAPTER_H
#define MODEL_ROUTER_ADAPTER_H

#include <string>
#include <vector>
#include <memory>

class ModelInterface;

class ModelRouterAdapter {

public:
    explicit ModelRouterAdapter(void* parent = nullptr);
    ~ModelRouterAdapter();

    bool initialize(const std::string& config_file_path);
    bool loadApiKeys();
    bool isReady() const { return m_router != nullptr && m_initialized; }

    std::vector<std::string> getAvailableModels() const;
    std::string selectBestModel(const std::string& task_type, const std::string& language, bool prefer_local = false);
    bool selectModel(const std::string& model_id);
    std::string getCurrentModel() const;

    void* getRouter();
    void* createRouter();
    void* getModel(const std::string& name);
    void* loadModel(const std::string& path);

private:
    void* m_parent;
    std::unique_ptr<ModelInterface> m_router;
    bool m_initialized = false;
};

#endif
