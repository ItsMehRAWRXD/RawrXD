#include "../src/win32app/AgentToolCallPolicy.h"
#include <iostream>
#include <string_view>
int main() {
    using rawrxd::agent::hasToolPayload;
    struct Case {std::string_view text; bool expected;};
    constexpr Case cases[] = {
        {"TOOL:edit file",true},{"tool:read file",true},
        {"TOOL: edit file",true},{"tool:\nrun",true},
        {"TOOL:",false},{"tool: ",false},{"TOOL:\r\n\t",false},
        {"Tool:edit",false},{"TOOL",false},{"ANSWER:ok",false},
        {"prefix TOOL:edit",false},{"",false},{"tool:0",true}
    };
    int failures=0;
    for(const auto& c:cases) {
        const bool ok=hasToolPayload(c.text)==c.expected;
        if(!ok) ++failures;
        std::cout<<(ok?"PASS ":"FAIL ")<<c.text<<'\n';
    }
    std::cout<<"AGENT_TOOL_POLICY assertions="<<(sizeof(cases)/sizeof(cases[0]))<<" failures="<<failures<<'\n';
    return failures?1:0;
}
