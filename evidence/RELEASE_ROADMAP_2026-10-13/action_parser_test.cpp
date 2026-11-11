#include <string>
#include <cctype>
#include <cstdio>
std::string Trim(const std::string& s) { size_t a=0,b=s.size(); while(a<b && std::isspace((unsigned char)s[a])) ++a; while(b>a && std::isspace((unsigned char)s[b-1])) --b; return s.substr(a,b-a); }
struct Action
{
    bool valid = false;  // a COMPLETE, dispatchable command was recognised
    bool finish = false;
    std::string tool, arg1, arg2;
    std::string raw;
};

Action ParseAction(const std::string& text)
{
    Action a;
    // The last line that starts a TOOL command.
    size_t lineStart = text.rfind("\nTOOL ");
    lineStart = (lineStart == std::string::npos) ? (text.rfind("TOOL ") == 0 ? 0 : std::string::npos) : lineStart + 1;
    if (lineStart == std::string::npos)
        return a;
    size_t lineEnd = text.find('\n', lineStart);
    const std::string line =
        text.substr(lineStart, lineEnd == std::string::npos ? std::string::npos : lineEnd - lineStart);
    const std::string t = Trim(line);
    // A nonempty argument can still be a partial token stream. Only a line
    // terminator closes read/bash/finish; write closes with its second @@.
    if (lineEnd == std::string::npos && t.rfind("TOOL write ", 0) != 0)
        return a;
    if (t.rfind("TOOL finish", 0) == 0 && Trim(t.substr(11)).empty())
    {
        a.valid = true;
        a.finish = true;
        a.tool = "finish";
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL read ", 0) == 0)
    {
        const std::string path = Trim(t.substr(10));
        if (path.empty())
            return a;
        a.valid = true;
        a.tool = "read";
        a.arg1 = path;
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL bash ", 0) == 0)
    {
        const std::string cmd = Trim(t.substr(10));
        if (cmd.empty())
            return a;
        a.valid = true;
        a.tool = "bash";
        a.arg1 = cmd;
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL write ", 0) == 0)
    {
        const size_t sp = t.find(' ', 11);
        if (sp == std::string::npos)
            return a;
        const std::string path = t.substr(11, sp - 11);
        if (path.empty())
            return a;
        const std::string command = text.substr(lineStart);
        const size_t a1 = command.find("@@", sp);
        if (a1 == std::string::npos)
            return a;  // no open delimiter: incomplete
        const size_t a2 = command.find("@@", a1 + 2);
        if (a2 == std::string::npos)
            return a;  // no close delimiter: incomplete
        const std::string body = command.substr(a1 + 2, a2 - (a1 + 2));
        if (body.empty())
            return a;
        a.valid = true;
        a.tool = "write";
        a.arg1 = path;
        a.arg2 = body;
        a.raw = command.substr(0, a2 + 2);
        return a;
    }
    return a;
}


int main() {
 int fails=0;
 auto check=[&](const char* text,bool valid,const char* body="") { auto a=ParseAction(text); if(a.valid!=valid || (valid && a.tool=="write" && a.arg2!=body)) { ++fails; std::printf("FAIL: %s\n",text); } };
 check("TOOL read calc.c",false);
 check("\nTOOL bash cl calc",false);
 check("TOOL finish",false);
 check("TOOL read calc.cpp\n",true);
 check("TOOL bash cl calc.cpp /Fecalc.exe\n",true);
 check("TOOL finish\n",true);
 check("TOOL write calc.cpp @@int main() {",false);
 check("TOOL write calc.cpp @@int main() {\n return 0;\n}@@",true,"int main() {\n return 0;\n}");
 check("TOOL read \n",false);
 check("TOOL finish extra\n",false);
 std::printf("ACTION_PARSER %s fails=%d\n",fails?"FAIL":"PASS",fails);
 return fails?1:0;
}