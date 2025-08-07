#pragma once

#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <algorithm>

class PolymorphicEngine {
private:
    std::mt19937 rng;
    
    // Lists of variable name components for generation
    std::vector<std::string> prefixes = {
        "var", "data", "obj", "item", "element", "node", "val", "tmp", "buf",
        "ptr", "ref", "info", "ctx", "state", "handle", "res", "param", "arg"
    };
    
    std::vector<std::string> suffixes = {
        "Data", "Info", "Value", "Buffer", "Array", "List", "Set", "Map",
        "Handler", "Manager", "Controller", "Service", "Helper", "Util", "Core"
    };
    
    // Lists of function name components
    std::vector<std::string> funcPrefixes = {
        "process", "handle", "execute", "run", "perform", "invoke", "call",
        "init", "setup", "prepare", "compute", "calculate", "transform"
    };
    
    std::vector<std::string> funcSuffixes = {
        "Data", "Operation", "Task", "Job", "Work", "Action", "Process",
        "Function", "Method", "Routine", "Procedure", "Algorithm"
    };

    // Junk instruction templates
    std::vector<std::string> junkInstructions = {
        "int junk_%d = %d + %d - %d;",
        "unsigned int tmp_%d = (%d << %d) | (%d >> %d);",
        "char dummy_%d[%d] = {0};",
        "volatile int vol_%d = %d ^ %d;",
        "static int stat_%d = %d * %d / %d;",
        "register int reg_%d = %d & 0x%X;",
        "const int const_%d = %d | %d;",
        "float float_%d = %d.0f / %d.0f;",
        "double dbl_%d = (double)%d * %d.%d;"
    };

public:
    PolymorphicEngine() : rng(std::random_device{}()) {}

    // Generate unique variable name
    std::string generateVarName() {
        std::uniform_int_distribution<> prefixDist(0, prefixes.size() - 1);
        std::uniform_int_distribution<> suffixDist(0, suffixes.size() - 1);
        std::uniform_int_distribution<> numDist(1000, 9999);
        
        return prefixes[prefixDist(rng)] + suffixes[suffixDist(rng)] + "_" + std::to_string(numDist(rng));
    }

    // Generate unique function name
    std::string generateFuncName() {
        std::uniform_int_distribution<> prefixDist(0, funcPrefixes.size() - 1);
        std::uniform_int_distribution<> suffixDist(0, funcSuffixes.size() - 1);
        std::uniform_int_distribution<> numDist(100, 999);
        
        return funcPrefixes[prefixDist(rng)] + funcSuffixes[suffixDist(rng)] + "_" + std::to_string(numDist(rng));
    }

    // Generate random junk code
    std::string generateJunkCode(int lines = 5) {
        std::stringstream junk;
        std::uniform_int_distribution<> instrDist(0, junkInstructions.size() - 1);
        std::uniform_int_distribution<> valueDist(1, 1000);
        std::uniform_int_distribution<> smallDist(1, 32);
        
        junk << "    // Polymorphic junk code\n";
        
        for (int i = 0; i < lines; i++) {
            std::string instruction = junkInstructions[instrDist(rng)];
            
            // Replace placeholders with random values
            char buffer[256];
            snprintf(buffer, sizeof(buffer), instruction.c_str(),
                     valueDist(rng), valueDist(rng), valueDist(rng), 
                     valueDist(rng), smallDist(rng), smallDist(rng),
                     valueDist(rng), valueDist(rng), valueDist(rng));
            
            junk << "    " << buffer << "\n";
        }
        
        return junk.str();
    }

    // Generate random control flow obfuscation
    std::string generateControlFlowObfuscation(const std::string& realCode) {
        std::stringstream obfuscated;
        std::uniform_int_distribution<> condDist(0, 100);
        
        // Random always-true condition
        int val1 = condDist(rng) + 1;
        int val2 = condDist(rng) + 1;
        
        obfuscated << "    if ((" << val1 << " * " << val2 << ") > 0) {\n";
        obfuscated << generateJunkCode(2);
        obfuscated << "        " << realCode << "\n";
        obfuscated << generateJunkCode(2);
        obfuscated << "    } else {\n";
        obfuscated << generateJunkCode(3);
        obfuscated << "    }\n";
        
        return obfuscated.str();
    }

    // Generate polymorphic wrapper for data
    std::string generateDataWrapper(const std::string& dataName, size_t dataSize) {
        std::stringstream wrapper;
        std::uniform_int_distribution<> methodDist(0, 2);
        
        switch (methodDist(rng)) {
            case 0: // Array with computed indices
                wrapper << "    // Polymorphic data access method 1\n";
                wrapper << "    for (size_t i = 0; i < " << dataSize << "; i++) {\n";
                wrapper << "        size_t idx = (i * 7 + 3) % " << dataSize << ";\n";
                wrapper << "        " << dataName << "[idx] = " << dataName << "[idx];\n";
                wrapper << "    }\n";
                break;
                
            case 1: // Pointer arithmetic
                wrapper << "    // Polymorphic data access method 2\n";
                wrapper << "    unsigned char* ptr = " << dataName << ";\n";
                wrapper << "    unsigned char* end = ptr + " << dataSize << ";\n";
                wrapper << "    while (ptr < end) { *ptr = *ptr; ptr++; }\n";
                break;
                
            case 2: // Reverse iteration
                wrapper << "    // Polymorphic data access method 3\n";
                wrapper << "    for (int i = " << dataSize - 1 << "; i >= 0; i--) {\n";
                wrapper << "        " << dataName << "[i] = " << dataName << "[i];\n";
                wrapper << "    }\n";
                break;
        }
        
        return wrapper.str();
    }

    // Generate polymorphic function call
    std::string generatePolymorphicCall(const std::string& funcName, const std::vector<std::string>& args) {
        std::stringstream call;
        std::uniform_int_distribution<> methodDist(0, 2);
        
        std::string argsStr;
        for (size_t i = 0; i < args.size(); i++) {
            argsStr += args[i];
            if (i < args.size() - 1) argsStr += ", ";
        }
        
        switch (methodDist(rng)) {
            case 0: // Direct call with junk
                call << generateJunkCode(2);
                call << "    " << funcName << "(" << argsStr << ");\n";
                call << generateJunkCode(2);
                break;
                
            case 1: // Function pointer
                call << "    auto fp_" << generateVarName() << " = &" << funcName << ";\n";
                call << generateJunkCode(1);
                call << "    (*fp_" << generateVarName() << ")(" << argsStr << ");\n";
                break;
                
            case 2: // Conditional always true
                call << "    if ((1 + 1) == 2) {\n";
                call << "        " << funcName << "(" << argsStr << ");\n";
                call << "    }\n";
                break;
        }
        
        return call.str();
    }

    // Randomize code structure
    std::string randomizeCodeStructure(const std::string& code) {
        std::stringstream randomized;
        std::vector<std::string> codeBlocks;
        
        // Split code into blocks (simplified - just by lines for now)
        std::istringstream stream(code);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty()) {
                codeBlocks.push_back(line);
            }
        }
        
        // Add junk between real code blocks
        for (size_t i = 0; i < codeBlocks.size(); i++) {
            if (i % 3 == 0) {
                randomized << generateJunkCode(1);
            }
            randomized << codeBlocks[i] << "\n";
        }
        
        return randomized.str();
    }

    // Generate polymorphic includes
    std::string generatePolymorphicIncludes() {
        std::vector<std::string> includes = {
            "#include <iostream>",
            "#include <vector>",
            "#include <string>",
            "#include <algorithm>",
            "#include <memory>",
            "#include <functional>",
            "#include <map>",
            "#include <set>",
            "#include <list>",
            "#include <deque>",
            "#include <queue>",
            "#include <stack>"
        };
        
        // Shuffle includes
        std::shuffle(includes.begin(), includes.end(), rng);
        
        std::stringstream result;
        // Take random subset
        std::uniform_int_distribution<> countDist(5, includes.size());
        int count = countDist(rng);
        
        for (int i = 0; i < count && i < includes.size(); i++) {
            result << includes[i] << "\n";
        }
        
        return result.str();
    }
};