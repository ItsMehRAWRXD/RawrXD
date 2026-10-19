#pragma once
// Stub native_agent.hpp for CLI-only builds

#include <string>

namespace CPUInference {
    class CPUInferenceEngine {
    public:
        bool LoadModel(const std::string&) { return false; }
    };
}

namespace RawrXD {
    class NativeAgent {
    public:
        explicit NativeAgent(CPUInference::CPUInferenceEngine*) {}
        void Ask(const std::string&) {}
        void Plan(const std::string&) {}
        void BugReport(const std::string&) {}
        void Edit(const std::string&, const std::string&) {}
        void Suggest(const std::string&) {}
        void HotPatch(const std::string&) {}
        void CreateReactServerPlan() {}
        void SetMaxMode(bool) {}
        void SetDeepThink(bool) {}
        void SetDeepResearch(bool) {}
        void SetNoRefusal(bool) {}
    };
}
