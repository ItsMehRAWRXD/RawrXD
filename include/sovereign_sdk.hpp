#pragma once

#include "sovereign_sdk.h"

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace sovereign {

class Error final : public std::runtime_error {
public:
    explicit Error(const std::string& msg) : std::runtime_error(msg) {}
};

class Engine final {
public:
    explicit Engine(const SovereignNodeConfig& cfg) {
        handle_ = Sovereign_Init(&cfg);
        if (!handle_) {
            throw Error("Sovereign_Init failed");
        }
    }

    ~Engine() {
        if (handle_) {
            Sovereign_Shutdown(handle_);
            handle_ = nullptr;
        }
    }

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    Engine(Engine&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    Engine& operator=(Engine&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                Sovereign_Shutdown(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    SovereignHandle raw() const { return handle_; }

    SovereignStatus status() const {
        SovereignStatus s{};
        if (Sovereign_GetStatus(handle_, &s) != 0) {
            throw Error("Sovereign_GetStatus failed");
        }
        return s;
    }

    SovereignModelHandle loadModel(const SovereignModelConfig& cfg) {
        auto m = Sovereign_LoadModel(handle_, &cfg);
        if (!m) {
            throw Error("Sovereign_LoadModel failed");
        }
        return m;
    }

    void unloadModel(SovereignModelHandle model) {
        if (Sovereign_UnloadModel(handle_, model) != 0) {
            throw Error("Sovereign_UnloadModel failed");
        }
    }

    SovereignTaskHandle submitTask(SovereignModelHandle model, const SovereignTaskParams& params) {
        auto task = Sovereign_SubmitTask(handle_, model, &params);
        if (!task) {
            throw Error("Sovereign_SubmitTask failed");
        }
        return task;
    }

    SovereignTaskHandle submitTaskWithHandle(SovereignModelHandle model, const SovereignTaskParams& params) {
        SovereignTaskWaitHandle waitHandle = nullptr;
        if (Sovereign_SubmitTaskWithHandle(handle_, model, &params, &waitHandle) != 0) {
            throw Error("Sovereign_SubmitTaskWithHandle failed");
        }
        return reinterpret_cast<SovereignTaskHandle>(waitHandle);
    }

    void waitTask(SovereignTaskHandle task, uint32_t timeoutMs = 0) {
        const int rc = Sovereign_WaitForTask(handle_, task, timeoutMs);
        if (rc < 0) {
            throw Error("Sovereign_WaitForTask failed");
        }
    }

    void waitTaskHandle(SovereignTaskHandle task, uint32_t timeoutMs = 0) {
        const int rc = Sovereign_WaitTaskHandle(handle_, reinterpret_cast<SovereignTaskWaitHandle>(task), timeoutMs);
        if (rc < 0) {
            throw Error("Sovereign_WaitTaskHandle failed");
        }
    }

    uint32_t taskState(SovereignTaskHandle task) const {
        uint32_t state = 0;
        if (Sovereign_GetTaskState(handle_, reinterpret_cast<SovereignTaskWaitHandle>(task), &state) != 0) {
            throw Error("Sovereign_GetTaskState failed");
        }
        return state;
    }

    void releaseTaskHandle(SovereignTaskHandle task) const {
        Sovereign_ReleaseTaskHandle(handle_, reinterpret_cast<SovereignTaskWaitHandle>(task));
    }

private:
    SovereignHandle handle_{nullptr};
};

class SemanticGraph final {
public:
    SemanticGraph(SovereignHandle engine, const std::string& rootPath, const std::vector<const char*>& patterns) {
        graph_ = Sovereign_LoadCodeBase(engine, rootPath.c_str(), patterns.data(), static_cast<uint32_t>(patterns.size()));
        if (!graph_) {
            throw Error("Sovereign_LoadCodeBase failed");
        }
    }

    SovereignGraphHandle raw() const { return graph_; }

    std::vector<uint32_t> query(const std::string& q, uint32_t maxResults = 128) const {
        std::vector<uint32_t> ids(maxResults, 0);
        std::vector<float> scores(maxResults, 0.0f);
        const int count = Sovereign_QuerySemanticGraph(graph_, q.c_str(), ids.data(), maxResults, scores.data());
        if (count < 0) {
            throw Error("Sovereign_QuerySemanticGraph failed");
        }
        ids.resize(static_cast<size_t>(count));
        return ids;
    }

private:
    SovereignGraphHandle graph_{nullptr};
};

}  // namespace sovereign
