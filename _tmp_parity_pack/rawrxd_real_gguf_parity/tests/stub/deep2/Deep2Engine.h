#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <cstdio>
namespace Deep2 {
struct EngineConfig{std::size_t hiddenDim=16,numLayers=1,numHeads=1,numKVHeads=1,headDim=16,vocabSize=32,intermediateDim=32,maxSeqLen=512,numThreads=1;bool useKVCache=true;};
struct ModelLoadDiag{int stageCode=0;std::string stageName,message;};
struct ModelWeights{};
class Deep2Engine {
public:
 bool initialize(const EngineConfig& c){cfg=c;return true;}
 void enableVulkan(bool){}
 void setVulkanStrictNoCpuFallback(bool){}
 void enableVerifiedSpeculation(bool,std::uint32_t=4){}
 bool loadModel(const std::string&,ModelLoadDiag*){return true;}
 std::string modelArchitecture() const{return "llama";}
 std::vector<int> tokenize(const std::string&) {return {1,2};}
 const EngineConfig& getConfig() const{return cfg;}
 bool embedToken(int,float*){return true;}
 bool forwardTokenAllLayers(float*,std::size_t){return true;}
 bool advancePersistentKv(){return true;}
 void computeLogits(const float*,float* p){for(std::size_t i=0;i<cfg.vocabSize;++i)p[i]=float(i);}
 void enableParityProbe(const char*,int){}
 void parityBeginStep(int){}
 void parityEmitLogitsTop10(const float*,std::size_t){}
 void disableParityProbe(){}
 std::uint64_t vulkanGemvFallbackCount()const{return 0;}
 std::uint64_t vulkanGemvSuccessCount()const{return 1;}
 bool isRealGpuForward()const{return true;}
 bool vulkanStrictViolation()const{return false;}
private:EngineConfig cfg{};
};
}
