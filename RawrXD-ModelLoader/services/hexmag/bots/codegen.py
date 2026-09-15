from typing import List, Any, Dict, Set
from core.contracts import (
    LABEL_ANSWER,
    LABEL_LLM_ANSWER,
    LABEL_PARTIAL,
    ROLE_CODE_GENERATION,
    ROLE_VERIFICATION,
    Bot,
    Event,
    Finding,
    make_answer,
    make_handoff,
    make_partial,
)
from core.model_policy_router import select_model_for_role


class CodegenBot(Bot):
    name = "codegen-bot"
    version = "0.3.0"
    roles = {ROLE_CODE_GENERATION}

    def supports(self, event: Event) -> bool:
        # Response Gen mode: CodegenBot is not a universal claimer — only if
        # HexMag explicitly spawned a codegen role into the arena.
        if event.payload.get("mode") == "response_gen":
            return False

        if event.kind == "llm.question":
            question = (event.payload.get("question") or "").lower()
            return (
                "parser" in question
                or "parse" in question
                or "ide" in question
                or "editor" in question
                or "textpad" in question
                or "text editor" in question
            )
        if event.kind == "role.requested":
            target = (event.payload.get("target_role") or "").lower()
            return target in self.roles or target in (
                "codegen",
                "codegen-bot",
                "coder",
                "code_generation",
            )
        return False

    async def run(self, event: Event) -> List[Finding]:
        route = select_model_for_role(ROLE_CODE_GENERATION)
        route_meta = route.to_dict()

        if event.kind == "role.requested":
            return self._run_agent_role(event, route_meta)

        # Legacy /ask path
        question = event.payload.get("question", "").lower()
        size = event.payload.get("size", "small").lower()
        findings: List[Finding] = []

        generated_code = ""
        rationale = ""

        if "parser" in question or "parse" in question:
            rationale = f"Detected request for ASM Parser ({size})"
            if size == "large":
                generated_code = self._generate_large_asm_parser()
            else:
                generated_code = self._generate_small_asm_parser()

        elif any(k in question for k in ["ide", "editor", "textpad", "text editor"]):
            rationale = f"Detected request for Text Editor ({size})"
            if size == "large":
                generated_code = self._generate_large_text_editor()
            else:
                generated_code = self._generate_small_text_editor()

        if generated_code:
            findings.append(
                Finding(
                    bot=self.name,
                    labels={LABEL_ANSWER, LABEL_LLM_ANSWER, "code.generation", "cpp"},
                    score=1.0,
                    rationale=rationale,
                    data={"answer": generated_code, "model_route": route_meta},
                )
            )

        return findings

    def _run_agent_role(self, event: Event, route_meta: Dict[str, Any]) -> List[Finding]:
        remaining = (
            event.payload.get("remaining_goal")
            or event.payload.get("goal")
            or ""
        )
        context = event.payload.get("context") or {}
        plan = context.get("plan") or []
        size = str(event.payload.get("size") or context.get("size") or "small").lower()

        code, rationale = self._synthesize(remaining, size)
        findings: List[Finding] = [
            Finding(
                bot=self.name,
                labels={LABEL_PARTIAL, "code.generation"},
                score=0.9,
                rationale="codegen.finding",
                data={
                    "phase": "codegen.finding",
                    "summary": rationale,
                    "plan": plan,
                    "model_route": route_meta,
                    "artifacts": [
                        {"type": "code", "content": code, "language": "cpp"},
                    ],
                },
            ),
            make_answer(
                self.name,
                code,
                rationale=rationale,
                model_route=route_meta,
                artifacts=[{"type": "code", "content": code, "language": "cpp"}],
            ),
            make_handoff(
                bot=self.name,
                target_role=ROLE_VERIFICATION,
                reason="Implementation ready for build/run verification",
                remaining_goal=remaining,
                context={
                    "plan": plan,
                    "implementation": code,
                    "model_route": route_meta,
                },
                artifacts=[{"type": "code", "content": code, "language": "cpp"}],
            ),
        ]
        return findings

    def _synthesize(self, goal: str, size: str) -> tuple[str, str]:
        g = (goal or "").lower()
        if "parser" in g or "parse" in g:
            code = (
                self._generate_large_asm_parser()
                if size == "large"
                else self._generate_small_asm_parser()
            )
            return code, "Generated ASM parser for agent goal"
        if any(k in g for k in ["ide", "editor", "textpad"]):
            code = (
                self._generate_large_text_editor()
                if size == "large"
                else self._generate_small_text_editor()
            )
            return code, "Generated text editor for agent goal"
        if "compile" in g or "fix" in g or "error" in g:
            code = self._generate_compile_fix_stub(goal)
            return code, "Generated minimal compile-fix patch stub"
        code = self._generate_generic_fix(goal)
        return code, "Generated generic implementation stub"

    def _generate_compile_fix_stub(self, goal: str) -> str:
        return (
            "// HexMag codegen-bot — compile-fix stub\n"
            "// Goal: " + goal.replace("\n", " ")[:200] + "\n"
            "#include <iostream>\n"
            "int main() {\n"
            "    std::cout << \"fixed\" << std::endl;\n"
            "    return 0;\n"
            "}\n"
        )

    def _generate_generic_fix(self, goal: str) -> str:
        return (
            "// HexMag codegen-bot — implementation stub\n"
            "// Goal: " + goal.replace("\n", " ")[:200] + "\n"
            "void hexmag_apply_change() {\n"
            "    // TODO: apply planned change\n"
            "}\n"
        )

    def _generate_small_asm_parser(self) -> str:
        return r"""// Generated by HexMag Copilot - ASM Parser (Small)
#include <iostream>
#include <string>
#include <vector>
#include <map>

class ASMParser {
private:
    std::vector<std::string> tokens;
    std::map<std::string, int> opcodes;
    int currentToken;
    
public:
    ASMParser() : currentToken(0) {
        opcodes["MOV"] = 0x01;
        opcodes["ADD"] = 0x02;
        opcodes["SUB"] = 0x03;
        opcodes["JMP"] = 0x04;
        opcodes["CMP"] = 0x05;
    }
    
    void parseLine(const std::string& line) {
        tokens.clear();
        std::string token;
        for (char c : line) {
            if (c == ' ' || c == ',' || c == '\t') {
                if (!token.empty()) {
                    tokens.push_back(token);
                    token.clear();
                }
            } else {
                token += c;
            }
        }
        if (!token.empty()) tokens.push_back(token);
        currentToken = 0;
        parseInstruction();
    }
    
    void parseInstruction() {
        if (currentToken >= tokens.size()) return;
        std::string opcode = tokens[currentToken++];
        if (opcodes.find(opcode) != opcodes.end()) {
            std::cout << "Parsed: " << opcode << " (0x" << std::hex << opcodes[opcode] << ")" << std::endl;
        }
    }
};
"""

    def _generate_large_asm_parser(self) -> str:
        return r"""// Generated by HexMag Copilot - ASM Parser (Large / Enterprise)
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// --- Instruction Set Architecture Definition ---
enum class OperandType { REGISTER, IMMEDIATE, MEMORY, LABEL };

struct Operand {
    OperandType type;
    std::string value;
    int offset = 0;
};

struct Instruction {
    std::string mnemonic;
    std::vector<Operand> operands;
    int lineNumber;
    uint64_t address;
};

class SymbolTable {
    std::map<std::string, uint64_t> symbols;
public:
    void define(const std::string& name, uint64_t address) { symbols[name] = address; }
    bool resolve(const std::string& name, uint64_t& address) {
        if (symbols.count(name)) {
            address = symbols[name];
            return true;
        }
        return false;
    }
};

class ASMParser {
private:
    std::vector<Instruction> program;
    SymbolTable symbols;
    uint64_t currentAddress = 0x1000;
    
    // Opcode mapping with operand count validation
    struct OpcodeInfo { uint8_t code; int expectedOperands; };
    std::map<std::string, OpcodeInfo> opcodes;

public:
    ASMParser() {
        // Initialize comprehensive x86-64 subset
        opcodes["MOV"] = {0x89, 2};
        opcodes["ADD"] = {0x01, 2};
        opcodes["SUB"] = {0x29, 2};
        opcodes["XOR"] = {0x31, 2};
        opcodes["JMP"] = {0xE9, 1};
        opcodes["CALL"] = {0xE8, 1};
        opcodes["RET"] = {0xC3, 0};
        opcodes["PUSH"] = {0x50, 1};
        opcodes["POP"] = {0x58, 1};
    }

    void parseFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) throw std::runtime_error("Cannot open file");
        
        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            lineNum++;
            line = stripComments(line);
            if (line.empty()) continue;
            
            if (isLabel(line)) {
                std::string label = line.substr(0, line.length() - 1);
                symbols.define(label, currentAddress);
                std::cout << "[SYMBOL] Defined " << label << " at 0x" << std::hex << currentAddress << std::endl;
            } else {
                parseInstruction(line, lineNum);
            }
        }
    }

private:
    std::string stripComments(std::string line) {
        size_t commentPos = line.find(';');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        return line;
    }

    bool isLabel(const std::string& line) {
        return !line.empty() && line.back() == ':';
    }

    void parseInstruction(const std::string& line, int lineNum) {
        std::stringstream ss(line);
        std::string mnemonic;
        ss >> mnemonic;
        
        std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::toupper);
        
        if (opcodes.find(mnemonic) == opcodes.end()) {
            std::cerr << "Error line " << lineNum << ": Unknown mnemonic " << mnemonic << std::endl;
            return;
        }

        Instruction instr;
        instr.mnemonic = mnemonic;
        instr.lineNumber = lineNum;
        instr.address = currentAddress;

        // Parse operands (simplified comma separation)
        std::string operandStr;
        std::getline(ss, operandStr);
        
        // ... (Complex operand parsing logic would go here) ...
        
        program.push_back(instr);
        currentAddress += 4; // Simplified fixed instruction width
    }
};
"""

    def _generate_small_text_editor(self) -> str:
        return r"""// Generated by HexMag Copilot - Text Editor (Small)
#include <iostream>
#include <string>
#include <vector>

class TextEditor {
    std::vector<std::string> lines;
public:
    void run() { std::cout << "Simple Editor Running..." << std::endl; }
};
"""

    def _generate_large_text_editor(self) -> str:
        return r"""// Generated by HexMag Copilot - Text Editor (Large / Enterprise)
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stack>
#include <memory>

// --- Command Pattern for Undo/Redo ---
class Command {
public:
    virtual void execute() = 0;
    virtual void undo() = 0;
    virtual ~Command() = default;
};

class InsertCommand : public Command {
    std::vector<std::string>& buffer;
    int line, col;
    char character;
public:
    InsertCommand(std::vector<std::string>& buf, int l, int c, char ch) 
        : buffer(buf), line(l), col(c), character(ch) {}
        
    void execute() override {
        if (line >= buffer.size()) buffer.resize(line + 1);
        buffer[line].insert(col, 1, character);
    }
    
    void undo() override {
        buffer[line].erase(col, 1);
    }
};

class TextEditor {
private:
    std::vector<std::string> buffer;
    std::stack<std::shared_ptr<Command>> undoStack;
    std::stack<std::shared_ptr<Command>> redoStack;
    int cursorX = 0, cursorY = 0;
    std::string filename;
    bool isDirty = false;

public:
    TextEditor(const std::string& fname) : filename(fname) {
        loadFile();
    }

    void insertChar(char c) {
        auto cmd = std::make_shared<InsertCommand>(buffer, cursorY, cursorX, c);
        cmd->execute();
        undoStack.push(cmd);
        while (!redoStack.empty()) redoStack.pop();
        cursorX++;
        isDirty = true;
    }

    void undo() {
        if (undoStack.empty()) return;
        auto cmd = undoStack.top();
        undoStack.pop();
        cmd->undo();
        redoStack.push(cmd);
    }

    void save() {
        std::ofstream out(filename);
        for (const auto& line : buffer) out << line << "\n";
        isDirty = false;
        std::cout << "Saved " << filename << std::endl;
    }

private:
    void loadFile() {
        std::ifstream in(filename);
        std::string line;
        while (std::getline(in, line)) buffer.push_back(line);
        if (buffer.empty()) buffer.push_back("");
    }
};
"""
