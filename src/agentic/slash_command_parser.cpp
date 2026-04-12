#include "slash_command_parser.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace RawrXD::Agentic {

// Tokenize input string by whitespace, respecting quoted strings
std::vector<std::string> SlashCommandParser::Tokenize(const std::string& input) {
    std::vector<std::string> tokens;
    std::string token;
    bool inQuote = false;
    
    for (size_t i = 0; i < input.length(); i++) {
        char c = input[i];
        
        if (c == '"' && (i == 0 || input[i-1] != '\\')) {
            inQuote = !inQuote;
        } else if ((isspace(c) || c == '\t') && !inQuote) {
            if (!token.empty()) {
                tokens.push_back(token);
                token.clear();
            }
        } else {
            token += c;
        }
    }
    
    if (!token.empty()) {
        tokens.push_back(token);
    }
    
    return tokens;
}

bool SlashCommandParser::IsSlashCommand(const std::string& input) {
    auto trimmed = input;
    trimmed.erase(0, trimmed.find_first_not_of(" \t"));
    return !trimmed.empty() && trimmed[0] == '/';
}

std::vector<std::string> SlashCommandParser::AvailableCommands() {
    return {
        "edit", "terminal", "search", "read", "write", "refactor", "git", "help"
    };
}

std::string SlashCommandParser::GetHelp(const std::string& command) {
    if (command.empty()) {
        return R"(
RawrXD Slash Commands:
  /edit <file1> [file2]...    Edit one or more files in sequence
  /terminal <cmd>             Execute terminal command and capture output
  /search <pattern>           Semantic code search in repository
  /read <file>                Read a file without editing
  /write <file> <content>     Write content to file
  /refactor <type> [sel]      Refactor code (extract, rename, simplify, etc)
  /git <action> [args]        Git operations (commit, diff, log, status)
  /help [command]             Show this help or help for specific command
)";
    } else if (command == "edit") {
        return "/edit FILE1 [FILE2] ...\nEdit one or more files sequentially with multi-file awareness.";
    } else if (command == "terminal") {
        return "/terminal COMMAND\nExecute terminal command. Output captured and returned.";
    } else if (command == "search") {
        return "/search PATTERN\nSemantic code search for PATTERN in repository.";
    } else if (command == "read") {
        return "/read FILE\nRead FILE without opening editor. Returns file contents.";
    } else if (command == "write") {
        return "/write FILE CONTENT\nWrite CONTENT to FILE (overwrites if exists).";
    } else if (command == "refactor") {
        return "/refactor TYPE [SELECTION]\nRefactor TYPE: extract, rename, simplify, inline";
    } else if (command == "git") {
        return "/git ACTION [ARGS]\nGit actions: commit, diff, log, status, blame";
    }
    return "Unknown command: " + command;
}

ParsedCommand SlashCommandParser::ParseEdit(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "edit";
    
    if (args.empty()) {
        cmd.error = "edit requires at least one file argument";
        return cmd;
    }
    
    // /edit file1 file2 file3...
    // Maps to: multi-file editing tool
    cmd.args = args;
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseTerminal(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "terminal";
    
    if (args.empty()) {
        cmd.error = "terminal requires a command";
        return cmd;
    }
    
    // Rejoin args as single command string
    std::string fullCmd = args[0];
    for (size_t i = 1; i < args.size(); i++) {
        fullCmd += " " + args[i];
    }
    
    cmd.args.push_back(fullCmd);
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseSearch(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "search";
    
    if (args.empty()) {
        cmd.error = "search requires a pattern";
        return cmd;
    }
    
    // /search pattern words...
    cmd.args = args;
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseRead(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "read";
    
    if (args.empty()) {
        cmd.error = "read requires a file path";
        return cmd;
    }
    
    cmd.args.push_back(args[0]); // first arg is file
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseWrite(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "write";
    
    if (args.size() < 2) {
        cmd.error = "write requires file and content";
        return cmd;
    }
    
    cmd.args.push_back(args[0]); // file
    
    // Rejoin remaining as content
    std::string content = args[1];
    for (size_t i = 2; i < args.size(); i++) {
        content += " " + args[i];
    }
    cmd.args.push_back(content);
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseRefactor(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "refactor";
    
    if (args.empty()) {
        cmd.error = "refactor requires a type (extract, rename, simplify, inline)";
        return cmd;
    }
    
    // /refactor type [selection]
    cmd.args = args;
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::ParseGit(const std::vector<std::string>& args) {
    ParsedCommand cmd;
    cmd.command = "git";
    
    if (args.empty()) {
        cmd.error = "git requires an action (commit, diff, log, status)";
        return cmd;
    }
    
    // /git action [args]...
    cmd.args = args;
    cmd.valid = true;
    return cmd;
}

ParsedCommand SlashCommandParser::Parse(const std::string& input) {
    ParsedCommand cmd;
    
    if (!IsSlashCommand(input)) {
        cmd.error = "not a slash command (must start with /)";
        return cmd;
    }
    
    // Tokenize
    auto tokens = Tokenize(input);
    if (tokens.empty()) {
        cmd.error = "empty command";
        return cmd;
    }
    
    // First token is /command
    std::string cmdToken = tokens[0];
    if (cmdToken[0] != '/' || cmdToken.length() < 2) {
        cmd.error = "invalid command format";
        return cmd;
    }
    
    std::string cmdName = cmdToken.substr(1); // Remove leading /
    
    // Rest are arguments
    std::vector<std::string> args(tokens.begin() + 1, tokens.end());
    
    // Dispatch to appropriate parser
    if (cmdName == "edit")     return ParseEdit(args);
    if (cmdName == "terminal") return ParseTerminal(args);
    if (cmdName == "search")   return ParseSearch(args);
    if (cmdName == "read")     return ParseRead(args);
    if (cmdName == "write")    return ParseWrite(args);
    if (cmdName == "refactor") return ParseRefactor(args);
    if (cmdName == "git")      return ParseGit(args);
    if (cmdName == "help") {
        cmd.command = "help";
        cmd.args = args;
        cmd.valid = true;
        return cmd;
    }
    
    cmd.error = "unknown command: " + cmdName;
    return cmd;
}

nlohmann::json ParsedCommand::ToToolCall() const {
    using json = nlohmann::json;
    
    json toolCall = json::object();
    
    // Map slash command to appropriate tool
    if (command == "edit") {
        toolCall["tool"] = "propose_multifile_edits";
        toolCall["args"] = json::object();
        json files = json::array();
        for (const auto& arg : args) {
            files.push_back(arg);
        }
        toolCall["args"]["files"] = files;
    } 
    else if (command == "terminal") {
        toolCall["tool"] = "run_terminal";
        toolCall["args"] = json::object();
        if (!args.empty()) {
            toolCall["args"]["command"] = args[0];
        }
    }
    else if (command == "search") {
        toolCall["tool"] = "semantic_search";
        toolCall["args"] = json::object();
        if (!args.empty()) {
            toolCall["args"]["query"] = args[0];
        }
    }
    else if (command == "read") {
        toolCall["tool"] = "read_file";
        toolCall["args"] = json::object();
        if (!args.empty()) {
            toolCall["args"]["path"] = args[0];
        }
    }
    else if (command == "write") {
        toolCall["tool"] = "write_file";
        toolCall["args"] = json::object();
        if (args.size() >= 2) {
            toolCall["args"]["path"] = args[0];
            toolCall["args"]["content"] = args[1];
        }
    }
    else if (command == "refactor") {
        toolCall["tool"] = "propose_multifile_edits"; // Use multi-file edits as base
        toolCall["args"] = json::object();
        if (!args.empty()) {
            toolCall["args"]["refactor_type"] = args[0];
        }
    }
    else if (command == "git") {
        toolCall["tool"] = "run_terminal";
        toolCall["args"] = json::object();
        std::string gitCmd = "git";
        for (const auto& arg : args) {
            gitCmd += " " + arg;
        }
        toolCall["args"]["command"] = gitCmd;
    }
    else if (command == "help") {
        toolCall["tool"] = "help";
        toolCall["args"] = json::object();
        if (!args.empty()) {
            toolCall["args"]["command"] = args[0];
        }
    }
    
    return toolCall;
}

} // namespace RawrXD::Agentic
