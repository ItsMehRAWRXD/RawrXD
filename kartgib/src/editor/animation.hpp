#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <filesystem>
#include <cstdint>
#include <array>
#include <functional>
#include <glm/glm.hpp>
#include <glm/gtc/quaternion.hpp>
#include <glm/gtc/matrix_transform.hpp>

namespace kartgib::editor {

using BoneID = uint32_t;
constexpr BoneID INVALID_BONE = 0xFFFFFFFF;

struct Bone {
    std::string name;
    BoneID id;
    BoneID parent = 0xFFFFFFFF;
    uint32_t childrenStart = 0;
    uint32_t childrenCount = 0;
    glm::mat4 bindPose;           // Bone transform in bind pose
    glm::mat4 inverseBindPose;    // Inverse bind pose matrix
    glm::vec3 localPosition = {0, 0, 0};
    glm::quat localRotation = {1, 0, 0, 0};
    glm::vec3 localScale = {1, 1, 1};
    bool isSkinned = false;
};

struct Skeleton {
    std::string name;
    std::string guid;
    std::vector<Bone> bones;
    std::unordered_map<std::string, uint32_t> boneNameToID;
    uint32_t rootBone = 0;
    uint32_t boneCount = 0;
    glm::mat4 globalInverseBindPose;
    glm::vec3 boundingBoxMin;
    glm::vec3 boundingBoxMax;
    float rootHeight = 1.0f;
    
    uint32_t getBoneID(const std::string& name) const {
        auto it = boneNameToID.find(name);
        return it != boneNameToID.end() ? it->second : INVALID_BONE;
    }
    
    const Bone* getBone(uint32_t id) const {
        if (id < bones.size()) return &bones[id];
        return nullptr;
    }
    
    Bone* getBone(uint32_t id) {
        if (id < bones.size()) return &bones[id];
        return nullptr;
    }
    
    const Bone* getBone(const std::string& name) const {
        auto it = boneNameToID.find(name);
        if (it != boneNameToID.end()) return &bones[it->second];
        return nullptr;
    }
    
    Bone* getBone(const std::string& name) {
        auto it = boneNameToID.find(name);
        if (it != boneNameToID.end()) return &bones[it->second];
        return nullptr;
    }
    
    void computeGlobalInverseBindPose() {
        globalInverseBindPose = bones[rootBone].inverseBindPose;
    }
    
    std::vector<glm::mat4> calculateBoneTransforms(const std::vector<glm::mat4>& localTransforms) const {
        std::vector<glm::mat4> globalTransforms(bones.size());
        for (size_t i = 0; i < bones.size(); ++i) {
            const Bone& bone = bones[i];
            if (bone.parent == INVALID_BONE) {
                globalTransforms[i] = localTransforms[i];
            } else {
                globalTransforms[i] = globalTransforms[bone.parent] * localTransforms[i];
            }
        }
        return globalTransforms;
    }
};

struct Keyframe {
    float time = 0.0f;
    glm::vec3 position = {0, 0, 0};
    glm::quat rotation = {1, 0, 0, 0};
    glm::vec3 scale = {1, 1, 1};
};

struct AnimationCurve {
    uint32_t boneIndex = INVALID_BONE;
    std::vector<Keyframe> positionKeys;
    std::vector<Keyframe> rotationKeys;
    std::vector<Keyframe> scaleKeys;
    
    // Interpolation
    enum class InterpolationType { Linear, Cubic, Step } interpolation = InterpolationType::Linear;
    float preInfinity = 0; // 0=Constant, 1=Linear, 2=Cycle, 3=CycleOffset, 4=Oscillate
    float postInfinity = 0;
    
    bool hasPositionKeys() const { return !positionKeys.empty(); }
    bool hasRotationKeys() const { return !rotationKeys.empty(); }
    bool hasScaleKeys() const { return !scaleKeys.empty(); }
    float getDuration() const {
        float maxTime = 0;
        for (const auto& k : positionKeys) maxTime = std::max(maxTime, k.time);
        for (const auto& k : rotationKeys) maxTime = std::max(maxTime, k.time);
        for (const auto& k : scaleKeys) maxTime = std::max(maxTime, k.time);
        return maxTime;
    }
};

struct AnimationClip {
    std::string name;
    std::string guid;
    float length = 0.0f;
    float frameRate = 60.0f;
    bool loop = true;
    bool loopTime = true;
    bool loopPose = true;
    float loopTimeStart = 0.0f;
    float loopTimeEnd = 0.0f;
    bool loopBlend = true;
    float loopBlendDuration = 0.0f;
    std::vector<AnimationCurve> curves;
    std::unordered_map<std::string, uint32_t> curveNameToIndex;
    
    uint32_t getCurveIndex(const std::string& boneName) const {
        auto it = curveNameToIndex.find(name);
        return it != curveNameToIndex.end() ? it->second : INVALID_BONE;
    }
    
    float getDuration() const { return length; }
    float getFrameRate() const { return frameRate; }
    float getFrameTime() const { return 1.0f / frameRate; }
    uint32_t getFrameCount() const { return static_cast<uint32_t>(length * frameRate); }
    
    void evaluate(float time, std::vector<glm::mat4>& outTransforms, const Skeleton& skeleton) const {
        if (curves.empty()) return;
        
        // Wrap time
        float t = time;
        if (loop) {
            t = fmodf(time, length);
            if (t < 0) t += length;
        } else {
            t = glm::clamp(t, 0.0f, length);
        }
        
        // Evaluate curves
        std::vector<glm::mat4> localTransforms(curves.size());
        for (size_t i = 0; i < curves.size(); ++i) {
            const auto& curve = curves[i];
            if (curve.boneIndex >= skeleton.bones.size()) continue;
            
            glm::mat4 localTransform = glm::mat4(1.0f);
            
            // Interpolate position
            if (curve.hasPositionKeys()) {
                float t = time;
                if (loop) t = fmodf(time, length);
                if (t < 0) t += length;
                else if (t > curve.positionKeys.back().time) t = curve.positionKeys.back().time;
                
                // Find keyframe interval
                size_t idx = 0;
                while (idx + 1 < curve.positionKeys.size() && curve.positionKeys[idx + 1].time <= t) ++idx;
                
                if (idx + 1 < curve.positionKeys.size()) {
                    const auto& k0 = curve.positionKeys[idx];
                    const auto& k1 = curve.positionKeys[idx + 1];
                    float t_local = (t - k0.time) / (k1.time - k0.time);
                    glm::vec3 pos = glm::mix(k0.position, k1.position, t_local);
                    localTransform[3] = glm::vec4(pos, 1.0f);
                } else {
                    localTransform[3] = glm::vec4(curve.positionKeys.back().position, 1.0f);
                }
            }
            
            // Interpolate rotation
            if (curve.hasRotationKeys()) {
                // Similar slerp for rotation
                glm::quat rot = {1, 0, 0, 0};
                localTransform = glm::mat4_cast(rot);
            }
            
            // Interpolate scale
            if (curve.hasScaleKeys()) {
                // Similar lerp for scale
            }
            
            // Apply to bone
            size_t boneIdx = curve.boneIndex;
            if (boneIdx < localTransforms.size()) {
                localTransforms[boneIdx] = localTransform;
            }
        }
    }
};

struct AnimationState {
    std::string clipName;
    float time = 0.0f;
    float speed = 1.0f;
    float weight = 1.0f;
    float normalizedTime = 0.0f;
    bool playing = false;
    bool loop = true;
    float speedMultiplier = 1.0f;
    float normalizedTime = 0.0f;
    bool loop = true;
};

struct AnimationLayer {
    std::string name;
    float weight = 1.0f;
    std::vector<AnimationState> states;
    std::string currentState;
    bool isAdditive = false;
    bool isOverriding = false;
    float weight = 1.0f;
    bool isPlaying = false;
};

struct AnimationStateMachine {
    struct State {
        std::string name;
        std::string clipGUID;
        float speed = 1.0f;
        float normalizedTime = 0.0f;
        bool loop = true;
        bool loopTime = true;
        bool loopPose = true;
        float speed = 1.0f;
        bool canTransitionToSelf = false;
        std::vector<std::string> transitions;
    };
    
    struct Transition {
        std::string fromState;
        std::string toState;
        float duration = 0.2f;
        float offset = 0.0f;
        bool hasExitTime = true;
        float exitTime = 1.0f;
        bool hasFixedDuration = true;
        float transitionDuration = 0.2f;
        float transitionOffset = 0.0f;
        bool canTransitionToSelf = false;
        bool orderedInterruption = true;
        bool canTransitionToSelf_ = false;
        std::vector<std::pair<std::string, float>> conditions; // param, threshold
        bool orderedInterruption_ = true;
        bool canTransitionToSelf__ = false;
    };
    
    std::string name;
    std::string guid;
    std::string entryState = "Entry";
    std::string exitState = "Exit";
    std::string anyState = "AnyState";
    std::unordered_map<std::string, State> states;
    std::vector<Transition> transitions;
    std::vector<std::string> parameters; // float, int, bool, trigger
    std::unordered_map<std::string, float> floatParams;
    std::unordered_map<std::string, int> intParams;
    std::unordered_map<std::string, bool> boolParams;
    std::unordered_map<std::string, bool> triggers;
    std::string currentState;
    std::string nextState;
    bool inTransition = false;
    float transitionProgress = 0.0f;
    float transitionDuration = 0.0f;
    float transitionOffset = 0.0f;
    
    void setFloat(const std::string& name, float value) {
        floatParams[name] = value;
    }
    
    void setInt(const std::string& name, int value) {
        intParams[name] = value;
    }
    
    void setBool(const std::string& name, bool value) {
        boolParams[name] = value;
    }
    
    void setTrigger(const std::string& name) {
        triggers[name] = true;
    }
    
    void resetTrigger(const std::string& name) {
        triggers.erase(name);
    }
    
    bool getBool(const std::string& name) const {
        auto it = boolParams.find(name);
        return it != boolParams.end() && it->second;
    }
    
    int getInt(const std::string& name) const {
        auto it = intParams.find(name);
        return it != intParams.end() ? it->second : 0;
    }
    
    float getFloat(const std::string& name) const {
        auto it = floatParams.find(name);
        return it != floatParams.end() ? it->second : 0.0f;
    }
    
    void update(float deltaTime) {
        // State machine update logic
        if (inTransition) {
            transitionProgress += deltaTime / transitionDuration;
            if (transitionProgress >= 1.0f) {
                currentState = nextState;
                inTransition = false;
                transitionProgress = 0.0f;
            }
        }
        
        // Check transitions
        if (!inTransition) {
            auto it = states.find(currentState);
            if (it != states.end()) {
                for (const auto& transition : transitions) {
                    if (transition.fromState == currentState || transition.fromState == "AnyState") {
                        bool canTransition = true;
                        for (const auto& [param, threshold] : conditions) {
                            // Check conditions
                            if (floatParams.count(param)) {
                                if (floatParams[param] < threshold) { canTransition = false; break; }
                            }
                        }
                        
                        if (canTransition) {
                            nextState = transition.toState;
                            inTransition = true;
                            transitionDuration = transition.duration;
                            transitionProgress = 0.0f;
                            break;
                        }
                    }
                }
            }
        }
        
        // Update current state animation
        auto it = states.find(currentState);
        if (it != states.end()) {
            // Update animation time
        }
    }
};

struct AnimatorController {
    std::string name;
    std::string guid;
    std::vector<AnimationLayer> layers;
    std::unordered_map<std::string, AnimationStateMachine> stateMachines;
    std::unordered_map<std::string, float> floatParams;
    std::unordered_map<std::string, int> intParams;
    std::unordered_map<std::string, bool> boolParams;
    std::unordered_map<std::string, bool> triggers;
    
    std::string rootStateMachine = "Base";
    float speed = 1.0f;
    float playbackSpeed = 1.0f;
    bool isPlaying = false;
    float normalizedTime = 0.0f;
    
    void setFloat(const std::string& name, float value) { floatParams[name] = value; }
    void setInt(const std::string& name, int value) { intParams[name] = value; }
    void setBool(const std::string& name, bool value) { boolParams[name] = value; }
    void setTrigger(const std::string& name) { triggers[name] = true; }
    void resetTrigger(const std::string& name) { triggers.erase(name); }
    
    float getFloat(const std::string& name) const { return floatParams.count(name) ? floatParams.at(name) : 0.0f; }
    int getInt(const std::string& name) const { return intParams.count(name) ? intParams.at(name) : 0; }
    bool getBool(const std::string& name) const { return boolParams.count(name) && boolParams.at(name); }
    bool getTrigger(const std::string& name) const { return triggers.count(name) && triggers.at(name); }
    
    void resetTrigger(const std::string& name) { triggers.erase(name); }
    
    void play(const std::string& stateName) {
        // Start playing state
    }
    
    void stop() {
        // Stop all layers
    }
    
    void update(float deltaTime) {
        // Update all layers and state machines
    }
    
    void setLayerWeight(int layerIndex, float weight) {
        if (layerIndex < layers.size()) {
            layers[layerIndex].weight = weight;
        }
    }
    
    float getLayerWeight(int layerIndex) const {
        if (layerIndex < layers.size()) return layers[layerIndex].weight;
        return 0.0f;
    }
    
    void setLayerAdditive(int layerIndex, bool additive) {
        if (layerIndex < layers.size()) {
            layers[layerIndex].isAdditive = additive;
        }
    }
    
    bool isLayerAdditive(int layerIndex) const {
        if (layerIndex < layers.size()) return layers[layerIndex].isAdditive;
        return false;
    }
    
    void playInLayer(int layerIndex, const std::string& clipGUID, float speed = 1.0f, float weight = 1.0f, float normalizedTime = 0.0f, bool loop = true) {
        if (layerIndex < layers.size()) {
            AnimationState state;
            state.clipName = clipGUID;
            state.speed = speed;
            state.weight = weight;
            state.normalizedTime = normalizedTime;
            state.playing = true;
            state.loop = loop;
            layers[layerIndex].states.push_back(state);
        }
    }
    
    void crossfadeInLayer(int layerIndex, const std::string& clipGUID, float duration, float speed = 1.0f, float weight = 1.0f, float normalizedTime = 0.0f, bool loop = true) {
        // Crossfade implementation
    }
    
    void stopLayer(int layerIndex) {
        if (layerIndex < layers.size()) {
            layers[layerIndex].states.clear();
        }
    }
};

struct SkinMeshComponent {
    EntityID meshID = INVALID_ENTITY;
    EntityID skeletonID = INVALID_ENTITY;
    std::vector<uint32_t> boneIndices;
    std::vector<glm::mat4> bindPoses;
    std::vector<glm::mat4> boneMatrices;
    std::vector<glm::vec4> boneWeights;
    std::vector<uint32_t> boneIndices;
    uint32_t maxBonesPerVertex = 4;
    uint64_t meshAssetID = 0;
    bool updateWhenOffscreen = false;
    bool skinnedMotionVectors = false;
    uint32_t quality = 2; // 0=Low, 1=Medium, 2=High
    bool updateWhenOffscreen = false;
    bool skinnedMotionVectors = false;
};

struct AnimationEvent {
    std::string functionName;
    float time = 0.0f;
    float floatParameter = 0.0f;
    int intParameter = 0;
    std::string stringParameter;
    uint64_t objectReference = 0;
    enum class Type { Float, Int, String, ObjectReference } type = Type::Float;
};

struct AnimationClipEvent {
    std::string functionName;
    float time = 0.0f;
    float floatParameter = 0.0f;
    int intParameter = 0;
    std::string stringParameter;
    uint64_t objectReference = 0;
    enum class Type { Float, Int, String, ObjectReference } type = Type::Float;
};

} // namespace kartgib::editor