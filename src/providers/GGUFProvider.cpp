#include "../agent_self_healing_orchestrator.hpp"
#include "../rawrxd.cpp"
#include <iostream>

namespace RawrXD {

class GGUFProvider : public IModelProvider {
public:
    GGUFProvider() : inference_engine(new Model()) {}
    ~GGUFProvider() { delete (Model*)inference_engine; }

    bool Load(const std::string& model) override {
        Model* m = (Model*)inference_engine;
        return m->load(model);
    }

    std::string Generate(const std::string& prompt, const GenerationConfig& cfg) override {
        Model* m = (Model*)inference_engine;
        std::string chat = "<|begin_of_sentence|>User: " + prompt + "\nAssistant:";
        auto toks = m->tok.encode(chat, false);
        toks.insert(toks.begin(), m->tok.bos);
        
        std::vector<float> lg;
        for (size_t i = 0; i < toks.size(); i++) lg = m->forward(toks[i], (int)i);
        
        Sampler s;
        s.temp = cfg.temperature;
        s.top_k = cfg.top_k;
        s.top_p = cfg.top_p;
        s.rep = cfg.repetition_penalty;
        
        int pos = (int)toks.size();
        std::string result;
        
        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < cfg.max_new_tokens; i++) {
            uint32_t t = s.sample(lg);
            if (t == m->tok.eos) break;
            result += m->tok.decode_token(t);
            s.obs(t);
            lg = m->forward(t, pos++);
        }
        auto end = std::chrono::steady_clock::now();
        
        last_tps = (double)result.size() / std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
        last_memory = m->decider.current_hot_bytes;
        
        return result;
    }

    ModelStats Stats() override {
        return { last_tps, last_memory };
    }

private:
    void* inference_engine;
    double last_tps = 0.0;
    size_t last_memory = 0;
};

std::shared_ptr<IModelProvider> CreateGGUFProvider() {
    return std::make_shared<GGUFProvider>();
}

} // namespace RawrXD

