#define RAWRXD_LIBRARY
#include "rawrxd_model_api.hpp"
#include "../rawrxd.cpp"

namespace RawrXD {
    
    // Private implementation encapsulating the unity build components
    class InternalModelInstance {
    public:
        Model m;
    };
    
    RawrXDModelEngine::RawrXDModelEngine() {
        impl = new InternalModelInstance();
    }
    
    RawrXDModelEngine::~RawrXDModelEngine() {
        delete impl;
    }
    
    bool RawrXDModelEngine::Initialize(const std::string& filepath) {
        return impl->m.load(filepath);
    }
    
    std::string RawrXDModelEngine::ExecuteInference(const std::string& prompt, const InternalGenerationConfig& cfg) {
        std::string chat = "<|begin_of_sentence|>User: " + prompt + "\nAssistant:";
        auto toks = impl->m.tok.encode(chat, false);
        toks.insert(toks.begin(), impl->m.tok.bos);
        
        std::vector<float> lg;
        for (size_t i = 0; i < toks.size(); i++) lg = impl->m.forward(toks[i], (int)i);
        
        Sampler s;
        s.temp = cfg.temperature;
        s.top_p = cfg.top_p;
        
        int pos = (int)toks.size();
        std::string result;
        
        for (size_t i = 0; i < cfg.max_tokens; i++) {
            uint32_t t = s.sample(lg);
            if (t == impl->m.tok.eos) break;
            result += impl->m.tok.decode_token(t);
            s.obs(t);
            lg = impl->m.forward(t, pos++);
        }
        
        return result;
    }
    
    void RawrXDModelEngine::HotpatchLayerWeights(uint32_t layer_id, const std::vector<float>& patched_weights) {
        // Integration point for layer hotpatching application
        // e.g. impl->m.update_tensor_data(...)
    }

    void RawrXDModelEngine::RevertLayerWeights(uint32_t layer_id) {
        // Rollback wrapper integration point
    }
}
