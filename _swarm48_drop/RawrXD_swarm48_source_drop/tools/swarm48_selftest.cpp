#include "rawrxd/swarm48/SwarmRuntime.hpp"
#include <iostream>
#include <unordered_map>

using namespace rawrxd::swarm48;

class FakeBackend final : public IInferenceAdapter {
public:
    ResidentModel load_shared(const ModelLoadRequest& req) override {
        ++loads[std::to_string(req.device)+"|"+req.model_path];
        return ResidentModel{next++, req.device, req.model_path, req.expected_weight_bytes};
    }
    void unload_shared(ModelHandle) override {}
    std::vector<DecodeResult> decode_batch(const ResidentModel&, std::span<const DecodeSequence> batch) override {
        std::vector<DecodeResult> out; out.reserve(batch.size());
        for (const auto& q : batch) out.push_back(DecodeResult{q.agent, true, false, static_cast<std::int32_t>(1000 + q.agent), {}});
        return out;
    }
    std::unordered_map<std::string,int> loads;
    ModelHandle next{1};
};

int main() {
    FakeBackend backend;
    SwarmRuntime rt(backend, SwarmRuntimeConfig{48, 16, 64*1024});
    constexpr DeviceId R9700=0, RX7800=1;
    rt.add_device(DeviceBudget{R9700,"Radeon AI PRO R9700",32ull<<30,2ull<<30,16,32,true}, KvPoolConfig{6ull<<30,256u<<10});
    rt.add_device(DeviceBudget{RX7800,"Radeon RX 7800 XT",16ull<<30,2ull<<30,8,16,true}, KvPoolConfig{3ull<<30,256u<<10});

    // 48 logical agents; only TWO physical model residencies (one per GPU).
    for (AgentId i=1;i<=48;++i) {
        const auto dev = i<=32 ? R9700 : RX7800;
        AgentSpec s{i, static_cast<TeamId>((i-1)/8), "worker", dev, "tiny-worker-2.2gb.gguf", 2200ull<<20, 100, 2, 8u<<10};
        rt.add_agent(std::move(s), {1,2,3});
        rt.set_runnable(i);
    }

    int guard=0;
    while (guard++ < 16) {
        rt.tick();
        bool done=true;
        for (AgentId i=1;i<=48;++i) {
            const auto* s=rt.get(i);
            if (!s || (s->state!=AgentState::completed && s->state!=AgentState::failed)) { done=false; break; }
        }
        if(done) break;
    }

    std::size_t completed=0, failed=0;
    for (AgentId i=1;i<=48;++i) {
        const auto* s=rt.get(i);
        completed += s && s->state==AgentState::completed;
        failed += s && s->state==AgentState::failed;
    }
    const bool sharing = rt.resident_model_count()==2 && backend.loads.size()==2;
    const bool pass = sharing && completed==48 && failed==0 && rt.kv_used_bytes(R9700)>0 && rt.kv_used_bytes(RX7800)>0;
    std::cout << "logical_agents=48\n"
              << "resident_weight_images=" << rt.resident_model_count() << "\n"
              << "completed=" << completed << " failed=" << failed << "\n"
              << "r9700_kv_bytes=" << rt.kv_used_bytes(R9700) << "\n"
              << "rx7800_kv_bytes=" << rt.kv_used_bytes(RX7800) << "\n"
              << "RAWRXD_SWARM48_CORE=" << (pass?"PASS":"FAIL") << "\n";
    return pass?0:1;
}
