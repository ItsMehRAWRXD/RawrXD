#pragma once
#include <string>
#include <nlohmann/json.hpp>
<<<<<<< HEAD

class Planner {
public:
    nlohmann::json plan(const std::string& humanWish);
private:
    nlohmann::json planQuantKernel(const std::string& wish);
    nlohmann::json planRelease(const std::string& wish);
    nlohmann::json planWebProject(const std::string& wish);
    nlohmann::json planSelfReplication(const std::string& wish);
    nlohmann::json planBulkFix(const std::string& wish);
    nlohmann::json planGeneric(const std::string& wish);
=======

using json = nlohmann::json;

class Planner {
public:
    // Convert natural language wish into structured task list
    json plan(const std::string& humanWish);

private:
    json planQuantKernel(const std::string& wish);
    json planRelease(const std::string& wish);
    json planWebProject(const std::string& wish);
    json planSelfReplication(const std::string& wish);
    json planGeneric(const std::string& wish);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
