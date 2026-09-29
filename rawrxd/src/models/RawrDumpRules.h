#pragma once
#include <string>
#include <vector>

// Rawr dump rules - Parses user-custom classification rules
// This authority parses user-custom classification rules for model dump

namespace rawrxd::models
{
    // Parse dump rules from config file
    void parseDumpRules(const std::string& configPath);
    
    // Get roots
    std::vector<std::string> getRoots();
    
    // Get alias
    std::string getAlias(const std::string& aliasName);
    
    // Get classification
    std::string getClassification(const std::string& rule);
    
    // Get route
    std::string getRoute(const std::string& rule);
    
    // Write dump rules receipt
    void writeDumpRulesReceipt();
}
