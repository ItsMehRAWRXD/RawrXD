#pragma once
#include <string>
<<<<<<< HEAD
#include <nlohmann/json.hpp>
#include <vector>
#include <functional>

=======
#include <functional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
class AutoBootstrap {
public:
    static AutoBootstrap* instance();
    static void installZeroTouch();
    static void startWithWish(const std::string& wish);
<<<<<<< HEAD
    void start();

    // Callbacks (replace Qt signals)
=======
    
    // Start autonomy loop with zero-touch input
    void start();
    
    // Callbacks replacing signals
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::function<void(const std::string&)> onWishReceived;
    std::function<void(const std::string&)> onPlanGenerated;
    std::function<void()> onExecutionStarted;
    std::function<void(bool)> onExecutionCompleted;
<<<<<<< HEAD

private:
    AutoBootstrap() = default;
    std::string grabWish();
    bool safetyGate(const std::string& wish);
    void startWithWishInternal(const std::string& wish);
    void executePlan(const std::string& wish, const nlohmann::json& plan);
=======
    
private:
    AutoBootstrap();
    
    // Grab wish from env-var > clipboard > dialog
    std::string grabWish();
    
    // Safety gate to prevent dangerous commands
    bool safetyGate(const std::string& wish);
    
    void startWithWishInternal(const std::string& wish);
    void executePlan(const std::string& wish, const json& plan);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    static AutoBootstrap* s_instance;
};
