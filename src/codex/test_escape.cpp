// Test JsonLite escape sequence handling
#include "JsonLite.hpp"
#include <cstdio>
#include <cstring>

int main() {
    // Test escape sequences
    auto json = RawrXD::Codex::JsonValue::Parse(R"({"code": "line1\nline2\ttab\"quote"})");
    const char* code = json["code"].AsString().c_str();
    
    printf("Testing escape sequences:\n");
    printf("Input:  line1\\nline2\\ttab\\\"quote\n");
    printf("Output: ");
    for (int i = 0; code[i]; i++) {
        if (code[i] == '\n') printf("\\n");
        else if (code[i] == '\t') printf("\\t");
        else if (code[i] == '"') printf("\\\"");
        else printf("%c", code[i]);
    }
    printf("\n");
    
    // Verify actual characters
    const char* str = json["code"].AsString().c_str();
    bool hasNewline = false;
    bool hasTab = false;
    bool hasQuote = false;
    
    for (int i = 0; str[i]; i++) {
        if (str[i] == '\n') hasNewline = true;
        if (str[i] == '\t') hasTab = true;
        if (str[i] == '"') hasQuote = true;
    }
    
    printf("\nVerification:\n");
    printf("Has newline: %s\n", hasNewline ? "YES" : "NO");
    printf("Has tab: %s\n", hasTab ? "YES" : "NO");
    printf("Has quote: %s\n", hasQuote ? "YES" : "NO");
    
    return (hasNewline && hasTab && hasQuote) ? 0 : 1;
}
