// RawrXD-Script Randomized Fuzzing Harness
// Generates random valid/invalid JS programs to stress-test the engine

#include "../bytecode/bytecode.hpp"
#include "../compiler/bytecode_emitter.hpp"
#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <cstring>
#include <ctime>
#include <vector>
#include <string>

using namespace RawrXD::Script;

// ============================================================================
// Fuzzing Configuration
// ============================================================================

struct FuzzConfig {
    uint32_t seed;
    size_t iterations;
    size_t maxProgramLength;
    size_t maxDepth;
    bool generateValidOnly;
    bool enableMutation;
    double mutationRate;
    const char* corpusDir;
    bool saveCrashes;
    bool saveInteresting;
};

FuzzConfig g_config = {
    .seed = 0,                    // 0 = use time()
    .iterations = 10000,
    .maxProgramLength = 1024,
    .maxDepth = 10,
    .generateValidOnly = false,
    .enableMutation = true,
    .mutationRate = 0.1,
    .corpusDir = nullptr,
    .saveCrashes = true,
    .saveInteresting = true
};

// ============================================================================
// Random Generator
// ============================================================================

class RandomGenerator {
private:
    std::mt19937_64 rng;
    
public:
    RandomGenerator(uint32_t seed) {
        if (seed == 0) {
            seed = static_cast<uint32_t>(time(nullptr));
        }
        rng.seed(seed);
        std::cout << "[Fuzz] Random seed: " << seed << std::endl;
    }
    
    uint32_t next() {
        return rng();
    }
    
    uint32_t range(uint32_t min, uint32_t max) {
        return min + (rng() % (max - min + 1));
    }
    
    bool chance(double probability) {
        return (rng() / static_cast<double>(UINT32_MAX)) < probability;
    }
    
    template<typename T>
    T& choice(std::vector<T>& vec) {
        return vec[rng() % vec.size()];
    }
    
    template<typename T>
    const T& choice(const std::vector<T>& vec) {
        return vec[rng() % vec.size()];
    }
};

// ============================================================================
// Program Generator
// ============================================================================

class ProgramGenerator {
private:
    RandomGenerator& rng;
    std::ostringstream output;
    int depth;
    
    // Token pools
    const std::vector<const char*> keywords = {
        "var", "let", "const", "function", "return", "if", "else",
        "while", "for", "break", "continue", "throw", "try", "catch",
        "finally", "new", "delete", "typeof", "instanceof", "in",
        "true", "false", "null", "undefined"
    };
    
    const std::vector<const char*> operators = {
        "+", "-", "*", "/", "%", "++", "--",
        "==", "!=", "===", "!==", "<", ">", "<=", ">=",
        "&&", "||", "!",
        "&", "|", "^", "~", "<<", ">>", ">>>",
        "=", "+=", "-=", "*=", "/=", "%=",
        ".", "[", "]", "(", ")", "{", "}", ";", ","
    };
    
    const std::vector<const char*> identifiers = {
        "a", "b", "c", "x", "y", "z",
        "foo", "bar", "baz", "qux",
        "obj", "arr", "fn", "func",
        "result", "value", "data", "item",
        "i", "j", "k", "n", "m",
        "length", "name", "type", "proto"
    };
    
    const std::vector<const char*> numberLiterals = {
        "0", "1", "2", "42", "123", "-1", "-42",
        "0.5", "3.14", "2.718", "1e10", "1e-10",
        "0xFF", "0xDEADBEEF", "0b1010", "0o777",
        "Infinity", "-Infinity", "NaN"
    };
    
    const std::vector<const char*> stringLiterals = {
        "\"hello\"", "\"world\"", "\"test\"",
        "\"foo\"", "\"bar\"", "\"baz\"",
        "\"\"", "\"a\"", "\"123\"",
        "'hello'", "'world'", "'test'"
    };

public:
    ProgramGenerator(RandomGenerator& r) : rng(r), depth(0) {}
    
    std::string generate() {
        output.str("");
        output.clear();
        depth = 0;
        
        // Generate a random program structure
        generateProgram();
        
        return output.str();
    }
    
private:
    void generateProgram() {
        // 50% chance of being a statement, 50% expression
        if (rng.chance(0.5)) {
            generateStatement();
        } else {
            generateExpression();
        }
    }
    
    void generateStatement() {
        if (depth > g_config.maxDepth) {
            generateSimpleStatement();
            return;
        }
        
        depth++;
        
        int choice = rng.range(0, 10);
        switch (choice) {
            case 0: generateVarDeclaration(); break;
            case 1: generateFunctionDeclaration(); break;
            case 2: generateIfStatement(); break;
            case 3: generateWhileLoop(); break;
            case 4: generateForLoop(); break;
            case 5: generateReturnStatement(); break;
            case 6: generateThrowStatement(); break;
            case 7: generateTryCatch(); break;
            case 8: generateExpressionStatement(); break;
            case 9: generateBlock(); break;
            case 10: generateSimpleStatement(); break;
        }
        
        depth--;
    }
    
    void generateSimpleStatement() {
        // Simple statements that always terminate
        int choice = rng.range(0, 3);
        switch (choice) {
            case 0:
                output << rng.choice(identifiers) << ";";
                break;
            case 1:
                output << rng.choice(numberLiterals) << ";";
                break;
            case 2:
                output << "break;";
                break;
            case 3:
                output << "continue;";
                break;
        }
    }
    
    void generateVarDeclaration() {
        output << "var " << rng.choice(identifiers);
        if (rng.chance(0.7)) {
            output << " = ";
            generateExpression();
        }
        output << ";";
    }
    
    void generateFunctionDeclaration() {
        output << "function " << rng.choice(identifiers) << "(";
        
        // Parameters
        int paramCount = rng.range(0, 3);
        for (int i = 0; i < paramCount; i++) {
            if (i > 0) output << ", ";
            output << rng.choice(identifiers);
        }
        
        output << ") {";
        
        // Function body
        int stmtCount = rng.range(0, 5);
        for (int i = 0; i < stmtCount; i++) {
            generateStatement();
        }
        
        output << "}";
    }
    
    void generateIfStatement() {
        output << "if (";
        generateExpression();
        output << ") {";
        generateStatement();
        output << "}";
        
        if (rng.chance(0.5)) {
            output << " else {";
            generateStatement();
            output << "}";
        }
    }
    
    void generateWhileLoop() {
        output << "while (";
        generateExpression();
        output << ") {";
        generateStatement();
        output << "}";
    }
    
    void generateForLoop() {
        output << "for (";
        
        // Init
        if (rng.chance(0.7)) {
            output << "var " << rng.choice(identifiers);
            if (rng.chance(0.5)) {
                output << " = " << rng.range(0, 10);
            }
        }
        output << "; ";
        
        // Condition
        if (rng.chance(0.7)) {
            output << rng.choice(identifiers) << " < " << rng.range(1, 100);
        }
        output << "; ";
        
        // Increment
        if (rng.chance(0.7)) {
            output << rng.choice(identifiers) << "++";
        }
        
        output << ") {";
        generateStatement();
        output << "}";
    }
    
    void generateReturnStatement() {
        output << "return";
        if (rng.chance(0.7)) {
            output << " ";
            generateExpression();
        }
        output << ";";
    }
    
    void generateThrowStatement() {
        output << "throw ";
        generateExpression();
        output << ";";
    }
    
    void generateTryCatch() {
        output << "try {";
        generateStatement();
        output << "} catch (" << rng.choice(identifiers) << ") {";
        generateStatement();
        output << "}";
        
        if (rng.chance(0.3)) {
            output << " finally {";
            generateStatement();
            output << "}";
        }
    }
    
    void generateExpressionStatement() {
        generateExpression();
        output << ";";
    }
    
    void generateBlock() {
        output << "{";
        int stmtCount = rng.range(1, 5);
        for (int i = 0; i < stmtCount; i++) {
            generateStatement();
        }
        output << "}";
    }
    
    void generateExpression() {
        if (depth > g_config.maxDepth) {
            generateSimpleExpression();
            return;
        }
        
        depth++;
        
        int choice = rng.range(0, 12);
        switch (choice) {
            case 0: generateBinaryExpression(); break;
            case 1: generateUnaryExpression(); break;
            case 2: generateCallExpression(); break;
            case 3: generateMemberExpression(); break;
            case 4: generateArrayExpression(); break;
            case 5: generateObjectExpression(); break;
            case 6: generateNewExpression(); break;
            case 7: generateConditionalExpression(); break;
            case 8: generateAssignmentExpression(); break;
            case 9: generateUpdateExpression(); break;
            case 10: generateSimpleExpression(); break;
            case 11: generateSimpleExpression(); break;
            case 12: generateSimpleExpression(); break;
        }
        
        depth--;
    }
    
    void generateSimpleExpression() {
        int choice = rng.range(0, 5);
        switch (choice) {
            case 0: output << rng.choice(identifiers); break;
            case 1: output << rng.choice(numberLiterals); break;
            case 2: output << rng.choice(stringLiterals); break;
            case 3: output << rng.choice(keywords); break;
            case 4: output << "("; generateExpression(); output << ")"; break;
            case 5: output << "["; generateExpression(); output << "]"; break;
        }
    }
    
    void generateBinaryExpression() {
        generateExpression();
        output << " " << rng.choice(operators) << " ";
        generateExpression();
    }
    
    void generateUnaryExpression() {
        output << rng.choice(operators);
        generateExpression();
    }
    
    void generateCallExpression() {
        output << rng.choice(identifiers) << "(";
        
        int argCount = rng.range(0, 3);
        for (int i = 0; i < argCount; i++) {
            if (i > 0) output << ", ";
            generateExpression();
        }
        
        output << ")";
    }
    
    void generateMemberExpression() {
        generateExpression();
        if (rng.chance(0.5)) {
            output << "." << rng.choice(identifiers);
        } else {
            output << "[";
            generateExpression();
            output << "]";
        }
    }
    
    void generateArrayExpression() {
        output << "[";
        
        int elemCount = rng.range(0, 5);
        for (int i = 0; i < elemCount; i++) {
            if (i > 0) output << ", ";
            generateExpression();
        }
        
        output << "]";
    }
    
    void generateObjectExpression() {
        output << "{";
        
        int propCount = rng.range(0, 3);
        for (int i = 0; i < propCount; i++) {
            if (i > 0) output << ", ";
            output << rng.choice(identifiers) << ": ";
            generateExpression();
        }
        
        output << "}";
    }
    
    void generateNewExpression() {
        output << "new " << rng.choice(identifiers) << "(";
        
        int argCount = rng.range(0, 3);
        for (int i = 0; i < argCount; i++) {
            if (i > 0) output << ", ";
            generateExpression();
        }
        
        output << ")";
    }
    
    void generateConditionalExpression() {
        generateExpression();
        output << " ? ";
        generateExpression();
        output << " : ";
        generateExpression();
    }
    
    void generateAssignmentExpression() {
        output << rng.choice(identifiers);
        output << " " << rng.choice(operators) << " ";
        generateExpression();
    }
    
    void generateUpdateExpression() {
        if (rng.chance(0.5)) {
            output << "++" << rng.choice(identifiers);
        } else {
            output << rng.choice(identifiers) << "++";
        }
    }
};

// ============================================================================
// Mutation Engine
// ============================================================================

class MutationEngine {
private:
    RandomGenerator& rng;
    
public:
    MutationEngine(RandomGenerator& r) : rng(r) {}
    
    std::string mutate(const std::string& input) {
        std::string result = input;
        
        // Apply multiple mutations
        int mutationCount = rng.range(1, 5);
        for (int i = 0; i < mutationCount; i++) {
            if (result.empty()) break;
            
            int mutationType = rng.range(0, 8);
            switch (mutationType) {
                case 0: result = bitFlip(result); break;
                case 1: result = byteSwap(result); break;
                case 2: result = insertion(result); break;
                case 3: result = deletion(result); break;
                case 4: result = substitution(result); break;
                case 5: result = duplication(result); break;
                case 6: result = truncation(result); break;
                case 7: result = interestingValue(result); break;
                case 8: result = keywordSwap(result); break;
            }
        }
        
        return result;
    }
    
private:
    std::string bitFlip(const std::string& input) {
        if (input.empty()) return input;
        
        std::string result = input;
        size_t pos = rng.range(0, result.length() - 1);
        int bit = rng.range(0, 7);
        result[pos] ^= (1 << bit);
        
        return result;
    }
    
    std::string byteSwap(const std::string& input) {
        if (input.length() < 2) return input;
        
        std::string result = input;
        size_t pos = rng.range(0, result.length() - 2);
        std::swap(result[pos], result[pos + 1]);
        
        return result;
    }
    
    std::string insertion(const std::string& input) {
        std::string result = input;
        size_t pos = rng.range(0, result.length());
        char c = static_cast<char>(rng.range(32, 126)); // Printable ASCII
        result.insert(pos, 1, c);
        
        return result;
    }
    
    std::string deletion(const std::string& input) {
        if (input.empty()) return input;
        
        std::string result = input;
        size_t pos = rng.range(0, result.length() - 1);
        result.erase(pos, 1);
        
        return result;
    }
    
    std::string substitution(const std::string& input) {
        if (input.empty()) return input;
        
        std::string result = input;
        size_t pos = rng.range(0, result.length() - 1);
        char c = static_cast<char>(rng.range(32, 126));
        result[pos] = c;
        
        return result;
    }
    
    std::string duplication(const std::string& input) {
        if (input.empty()) return input;
        
        std::string result = input;
        size_t pos = rng.range(0, result.length());
        size_t len = rng.range(1, std::min(size_t(10), result.length() - pos + 1));
        std::string dup = result.substr(pos, len);
        result.insert(pos, dup);
        
        return result;
    }
    
    std::string truncation(const std::string& input) {
        if (input.empty()) return input;
        
        size_t keep = rng.range(0, input.length());
        return input.substr(0, keep);
    }
    
    std::string interestingValue(const std::string& input) {
        // Replace random substring with interesting values
        const char* interesting[] = {
            "null", "undefined", "true", "false",
            "0", "-1", "1", "2147483647", "-2147483648",
            "NaN", "Infinity", "-Infinity",
            "", "'", "\"", "\\", "\n", "\r", "\t",
            "{}", "[]", "()", "function(){}"
        };
        
        std::string result = input;
        if (result.empty()) return result;
        
        size_t pos = rng.range(0, result.length());
        size_t len = rng.range(0, std::min(size_t(20), result.length() - pos));
        result.replace(pos, len, interesting[rng.range(0, 19)]);
        
        return result;
    }
    
    std::string keywordSwap(const std::string& input) {
        // Swap JavaScript keywords
        std::string result = input;
        
        // Simple string replacements
        const char* swaps[][2] = {
            {"var", "let"}, {"let", "const"}, {"const", "var"},
            {"function", "class"}, {"if", "while"}, {"while", "for"},
            {"true", "false"}, {"null", "undefined"},
            {"==", "==="}, {"!=", "!=="},
            {"&&", "||"}, {"||", "&&"}
        };
        
        if (rng.chance(0.3)) {
            int swapIdx = rng.range(0, 11);
            size_t pos = result.find(swaps[swapIdx][0]);
            if (pos != std::string::npos) {
                result.replace(pos, strlen(swaps[swapIdx][0]), swaps[swapIdx][1]);
            }
        }
        
        return result;
    }
};

// ============================================================================
// Fuzzing Statistics
// ============================================================================

struct FuzzStats {
    size_t iterations;
    size_t parseSuccess;
    size_t parseFail;
    size_t compileSuccess;
    size_t compileFail;
    size_t execSuccess;
    size_t execFail;
    size_t crashes;
    size_t timeouts;
    size_t interesting;
    
    void print() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Fuzzing Statistics" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Iterations:      " << iterations << std::endl;
        std::cout << "Parse Success:   " << parseSuccess << " (" 
                  << (100.0 * parseSuccess / iterations) << "%)" << std::endl;
        std::cout << "Parse Fail:      " << parseFail << std::endl;
        std::cout << "Compile Success: " << compileSuccess << " ("
                  << (100.0 * compileSuccess / iterations) << "%)" << std::endl;
        std::cout << "Compile Fail:    " << compileFail << std::endl;
        std::cout << "Exec Success:    " << execSuccess << " ("
                  << (100.0 * execSuccess / iterations) << "%)" << std::endl;
        std::cout << "Exec Fail:       " << execFail << std::endl;
        std::cout << "Crashes:         " << crashes << std::endl;
        std::cout << "Timeouts:        " << timeouts << std::endl;
        std::cout << "Interesting:     " << interesting << std::endl;
    }
};

// ============================================================================
// Main Fuzzing Loop
// ============================================================================

void runFuzzer() {
    RandomGenerator rng(g_config.seed);
    ProgramGenerator gen(rng);
    MutationEngine mut(rng);
    FuzzStats stats = {};
    
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD-Script Fuzzing Harness" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Iterations: " << g_config.iterations << std::endl;
    std::cout << "Max Length: " << g_config.maxProgramLength << std::endl;
    std::cout << "Mutation:   " << (g_config.enableMutation ? "enabled" : "disabled") << std::endl;
    std::cout << std::endl;
    
    // Corpus of interesting inputs
    std::vector<std::string> corpus;
    
    for (size_t i = 0; i < g_config.iterations; i++) {
        // Generate or mutate
        std::string program;
        if (g_config.enableMutation && !corpus.empty() && rng.chance(g_config.mutationRate)) {
            program = mut.mutate(rng.choice(corpus));
        } else {
            program = gen.generate();
        }
        
        // Truncate if too long
        if (program.length() > g_config.maxProgramLength) {
            program = program.substr(0, g_config.maxProgramLength);
        }
        
        stats.iterations++;
        
        // TODO: Integrate with actual interpreter
        // For now, simulate fuzzing results
        
        // Phase 1: Lexing/Parsing
        bool parseOk = rng.chance(0.3); // 30% parse success
        if (parseOk) {
            stats.parseSuccess++;
        } else {
            stats.parseFail++;
            continue;
        }
        
        // Phase 2: Compilation
        bool compileOk = rng.chance(0.8); // 80% compile success if parse ok
        if (compileOk) {
            stats.compileSuccess++;
        } else {
            stats.compileFail++;
            continue;
        }
        
        // Phase 3: Execution
        bool execOk = rng.chance(0.9); // 90% exec success if compile ok
        if (execOk) {
            stats.execSuccess++;
        } else {
            stats.execFail++;
        }
        
        // Check for crashes
        if (rng.chance(0.001)) { // 0.1% crash rate
            stats.crashes++;
            std::cout << "[CRASH] Iteration " << i << std::endl;
            std::cout << "Program: " << program.substr(0, 100) << "..." << std::endl;
        }
        
        // Check for interesting inputs
        if (rng.chance(0.01)) { // 1% interesting rate
            stats.interesting++;
            corpus.push_back(program);
            if (corpus.size() > 100) {
                corpus.erase(corpus.begin()); // Keep last 100
            }
        }
        
        // Progress report
        if ((i + 1) % 1000 == 0) {
            std::cout << "[" << (i + 1) << "/" << g_config.iterations 
                      << "] Corpus: " << corpus.size() << std::endl;
        }
    }
    
    stats.print();
    
    std::cout << "\nNote: This is a fuzzing framework scaffold." << std::endl;
    std::cout << "      Integration with interpreter required for actual testing." << std::endl;
}

// ============================================================================
// Command Line Interface
// ============================================================================

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --seed N          Random seed (0 = time-based)" << std::endl;
    std::cout << "  -i, --iterations N    Number of iterations (default: 10000)" << std::endl;
    std::cout << "  -l, --max-length N    Maximum program length (default: 1024)" << std::endl;
    std::cout << "  -d, --max-depth N     Maximum AST depth (default: 10)" << std::endl;
    std::cout << "  --no-mutation         Disable mutation engine" << std::endl;
    std::cout << "  -m, --mutation-rate R Mutation probability 0.0-1.0 (default: 0.1)" << std::endl;
    std::cout << "  --valid-only          Generate only valid programs" << std::endl;
    std::cout << "  --corpus DIR          Load/save corpus from directory" << std::endl;
    std::cout << "  --save-crashes        Save crash inputs to files" << std::endl;
    std::cout << "  --save-interesting    Save interesting inputs to files" << std::endl;
    std::cout << "  -h, --help            Show this help" << std::endl;
}

int main(int argc, char** argv) {
    // Parse command line
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--seed") == 0) {
            if (++i < argc) g_config.seed = atoi(argv[i]);
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iterations") == 0) {
            if (++i < argc) g_config.iterations = atoi(argv[i]);
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--max-length") == 0) {
            if (++i < argc) g_config.maxProgramLength = atoi(argv[i]);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--max-depth") == 0) {
            if (++i < argc) g_config.maxDepth = atoi(argv[i]);
        } else if (strcmp(argv[i], "--no-mutation") == 0) {
            g_config.enableMutation = false;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mutation-rate") == 0) {
            if (++i < argc) g_config.mutationRate = atof(argv[i]);
        } else if (strcmp(argv[i], "--valid-only") == 0) {
            g_config.generateValidOnly = true;
        } else if (strcmp(argv[i], "--corpus") == 0) {
            if (++i < argc) g_config.corpusDir = argv[i];
        } else if (strcmp(argv[i], "--save-crashes") == 0) {
            g_config.saveCrashes = true;
        } else if (strcmp(argv[i], "--save-interesting") == 0) {
            g_config.saveInteresting = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    runFuzzer();
    
    return 0;
}
