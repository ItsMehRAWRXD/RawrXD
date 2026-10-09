#pragma once
// RawrXD Deep2: offline C++17 tool-call protocol, schema validation, dispatch,
// observation feedback and bounded agent loop. No dependencies beyond STL.
#include "Deep2Steering.hpp"
#include <cctype>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace rawrxd::deep2 {
namespace json {
struct Value {
    enum Kind { Null, Boolean, Number, String, Array, Object } kind = Null;
    bool boolean = false;
    double number = 0;
    std::string str;
    std::vector<Value> array;
    std::map<std::string, Value> object;
    static Value text(std::string s) { Value v; v.kind=String; v.str=std::move(s); return v; }
    static Value obj() { Value v; v.kind=Object; return v; }
    static Value arr() { Value v; v.kind=Array; return v; }
    static Value flag(bool b) { Value v; v.kind=Boolean; v.boolean=b; return v; }
    const Value* get(const std::string& k) const { if(kind!=Object)return nullptr; auto it=object.find(k); return it==object.end()?nullptr:&it->second; }
};
inline std::string quote(const std::string& s) {
    std::string r="\""; const char* hex="0123456789abcdef";
    for(unsigned char c:s) { switch(c) {
        case '"':r+="\\\"";break;case '\\':r+="\\\\";break;case '\n':r+="\\n";break;
        case '\r':r+="\\r";break;case '\t':r+="\\t";break;
        default: if(c<32){r+="\\u00";r+=hex[c>>4];r+=hex[c&15];}else r+=char(c);
    }} return r+'"';
}
inline std::string dump(const Value& v) {
    switch(v.kind) {
        case Value::Null:return "null";case Value::Boolean:return v.boolean?"true":"false";
        case Value::Number:{std::ostringstream o;o.precision(17);o<<v.number;return o.str();}
        case Value::String:return quote(v.str);
        case Value::Array:{std::string r="[";for(auto& x:v.array){if(r.size()>1)r+=',';r+=dump(x);}return r+"]";}
        case Value::Object:{std::string r="{";for(auto& kv:v.object){if(r.size()>1)r+=',';r+=quote(kv.first)+":"+dump(kv.second);}return r+"}";}
    } return "null";
}
class Parser {
    const std::string& s; size_t i=0; unsigned depth=0;
    void ws(){while(i<s.size() && (s[i]==' '||s[i]=='\n'||s[i]=='\t'||s[i]=='\r'))++i;}
    bool consume(char c){ws();if(i<s.size()&&s[i]==c){++i;return true;}return false;}
    bool literal(const char* p){size_t n=std::char_traits<char>::length(p);if(s.compare(i,n,p)==0){i+=n;return true;}return false;}
    std::string string(){if(!consume('"'))throw std::runtime_error("expected string");std::string r;
        bool closed=false;while(i<s.size()){unsigned char c=s[i++];if(c=='"'){closed=true;break;}if(c<32)throw std::runtime_error("control character");
        if(c!='\\'){r+=char(c);continue;}if(i>=s.size())throw std::runtime_error("bad escape");char e=s[i++];
        switch(e){case '"':r+='"';break;case '\\':r+='\\';break;case '/':r+='/';break;case 'n':r+='\n';break;
        case 'r':r+='\r';break;case 't':r+='\t';break;case 'b':r+='\b';break;case 'f':r+='\f';break;
        case 'u':{if(i+4>s.size())throw std::runtime_error("bad unicode");unsigned code=0;for(int k=0;k<4;++k){char h=s[i++];code<<=4;if(h>='0'&&h<='9')code+=h-'0';else if(h>='a'&&h<='f')code+=h-'a'+10;else if(h>='A'&&h<='F')code+=h-'A'+10;else throw std::runtime_error("bad unicode");}
          if(code>=0xD800&&code<=0xDFFF)throw std::runtime_error("surrogate escape unsupported");
          if(code<128)r+=char(code);else if(code<2048){r+=char(0xC0|(code>>6));r+=char(0x80|(code&63));}else{r+=char(0xE0|(code>>12));r+=char(0x80|((code>>6)&63));r+=char(0x80|(code&63));}break;}
        default:throw std::runtime_error("bad escape");}}
        if(!closed)throw std::runtime_error("unterminated string");
        return r;
    }
    Value value(){ws();if(++depth>48)throw std::runtime_error("json nesting limit");Value v;
        if(i>=s.size())throw std::runtime_error("unexpected eof");
        char c=s[i];
        if(c=='"')v=Value::text(string());
        else if(c=='{'){++i;v=Value::obj();if(!consume('}')){do{std::string k=string();if(!consume(':'))throw std::runtime_error("expected colon");Value x=value();if(!v.object.emplace(k,std::move(x)).second)throw std::runtime_error("duplicate key");if(consume('}'))break;if(!consume(','))throw std::runtime_error("expected comma");}while(true);}}
        else if(c=='['){++i;v=Value::arr();if(!consume(']')){do{v.array.push_back(value());if(consume(']'))break;if(!consume(','))throw std::runtime_error("expected comma");}while(true);}}
        else if(literal("true"))v=Value::flag(true);else if(literal("false"))v=Value::flag(false);
        else if(literal("null"))v=Value{};
        else if(c=='-'||(c>='0'&&c<='9')){size_t start=i;if(s[i]=='-')++i;if(i>=s.size())throw std::runtime_error("bad number");if(s[i]=='0')++i;else{if(s[i]<'1'||s[i]>'9')throw std::runtime_error("bad number");while(i<s.size()&&std::isdigit((unsigned char)s[i]))++i;}
            if(i<s.size()&&s[i]=='.'){++i;size_t before=i;while(i<s.size()&&std::isdigit((unsigned char)s[i]))++i;if(i==before)throw std::runtime_error("bad decimal");}
            if(i<s.size()&&(s[i]=='e'||s[i]=='E')){++i;if(i<s.size()&&(s[i]=='+'||s[i]=='-'))++i;size_t before=i;while(i<s.size()&&std::isdigit((unsigned char)s[i]))++i;if(i==before)throw std::runtime_error("bad exponent");}
            v.kind=Value::Number;v.number=std::stod(s.substr(start,i-start));if(!std::isfinite(v.number))throw std::runtime_error("nonfinite number");}
        else throw std::runtime_error("invalid json");
        --depth;return v;
    }
public:explicit Parser(const std::string& x):s(x){} Value parse(){Value v=value();ws();if(i!=s.size())throw std::runtime_error("trailing json");return v;}
};
inline Value parse(const std::string& s){if(s.size()>1024*1024)throw std::runtime_error("json too large");return Parser(s).parse();}
} // json

struct ArgSpec { std::string name; json::Value::Kind kind; bool required=true; };
struct ToolSchema { std::string name, description; std::vector<ArgSpec> args; bool allow_extra=false; };
struct ToolCall { std::string id, name; json::Value args; };
struct ToolObservation { std::string id, name; bool ok=false; std::string output, error; };
inline bool Validate(const ToolSchema& schema,const json::Value& args,std::string& error){
    if(args.kind!=json::Value::Object){error="arguments must be object";return false;}
    for(const auto& a:schema.args){const auto* v=args.get(a.name);if(!v){if(a.required){error="missing: "+a.name;return false;}continue;}if(v->kind!=a.kind){error="wrong type: "+a.name;return false;}}
    if(!schema.allow_extra)for(const auto& kv:args.object){bool found=false;for(const auto& a:schema.args)if(a.name==kv.first)found=true;if(!found){error="unknown argument: "+kv.first;return false;}}
    return true;
}
inline ToolCall ParseToolCall(const std::string& serialized){
    const auto root=json::parse(serialized);const json::Value* v=&root;
    // Accept a standalone call or a single OpenAI-style tool_calls envelope.
    if(const auto* calls=root.get("tool_calls")){if(calls->kind!=json::Value::Array||calls->array.size()!=1)throw std::runtime_error("expected exactly one tool call");v=&calls->array[0];}
    if(v->kind!=json::Value::Object)throw std::runtime_error("tool call must be object");
    ToolCall c; if(auto id=v->get("id")){if(id->kind!=json::Value::String)throw std::runtime_error("bad id");c.id=id->str;}
    if(auto f=v->get("function")){if(f->kind!=json::Value::Object)throw std::runtime_error("bad function");v=f;}
    auto n=v->get("name"),a=v->get("arguments");if(!n||n->kind!=json::Value::String||!a)throw std::runtime_error("missing name/arguments");
    c.name=n->str;c.args=a->kind==json::Value::String?json::parse(a->str):*a;
    if(c.name.empty()||c.name.size()>128||c.id.size()>128)throw std::runtime_error("invalid call identity");
    return c;
}
class ToolRegistry {
public: using Handler=std::function<ToolObservation(const ToolCall&)>;
private: struct Entry{ToolSchema schema;Handler handler;};std::map<std::string,Entry> entries_;
public:
    bool Register(ToolSchema schema,Handler handler){if(schema.name.empty()||!handler)return false;std::string name=schema.name;return entries_.emplace(std::move(name),Entry{std::move(schema),std::move(handler)}).second;}
    const ToolSchema* Find(const std::string& name)const{auto it=entries_.find(name);return it==entries_.end()?nullptr:&it->second.schema;}
    ToolObservation Dispatch(const ToolCall& call)const{
        ToolObservation o;o.id=call.id;o.name=call.name;auto it=entries_.find(call.name);
        if(it==entries_.end()){o.error="UNKNOWN_TOOL";return o;}
        if(!Validate(it->second.schema,call.args,o.error))return o;
        try{o=it->second.handler(call);o.id=call.id;o.name=call.name;}catch(const std::exception& e){o.ok=false;o.error=std::string("TOOL_EXCEPTION: ")+e.what();}catch(...){o.ok=false;o.error="TOOL_EXCEPTION";}
        constexpr size_t max_output=64*1024;if(o.output.size()>max_output){o.output.resize(max_output);o.output+="\n[TRUNCATED]";}return o;
    }
};
inline std::string ObservationJson(const ToolObservation& o){json::Value v=json::Value::obj();v.object["tool_call_id"]=json::Value::text(o.id);v.object["name"]=json::Value::text(o.name);v.object["ok"]=json::Value::flag(o.ok);v.object["output"]=json::Value::text(o.output);v.object["error"]=json::Value::text(o.error);return json::dump(v);}
struct AgentStep { bool final=false;std::string content; };
struct AgentResult { bool ok=false;std::string answer,error;std::vector<ToolObservation> observations; };
// Generator returns a final answer or a structured tool-call JSON string.
// It is invoked again with an observation message after every dispatched tool.
using GenerateStep=std::function<AgentStep(const std::vector<std::string>&)>;
inline AgentResult RunAgent(const ToolRegistry& registry,GenerateStep generate,
                            std::vector<std::string> messages,size_t max_calls=8){
    AgentResult r;if(!generate){r.error="NO_GENERATOR";return r;}
    if(max_calls==0||max_calls>64){r.error="INVALID_BUDGET";return r;}
    for(size_t step=0;step<=max_calls;++step){
        AgentStep g;try{g=generate(messages);}catch(const std::exception& e){r.error=std::string("GENERATION_FAILED: ")+e.what();return r;}
        if(g.final){r.ok=true;r.answer=g.content;return r;}
        if(step==max_calls){r.error="TOOL_BUDGET_EXHAUSTED";return r;}
        ToolCall call;try{call=ParseToolCall(g.content);}catch(const std::exception& e){r.error=std::string("INVALID_TOOL_CALL: ")+e.what();return r;}
        ToolObservation obs=registry.Dispatch(call);r.observations.push_back(obs);
        messages.push_back(std::string("assistant_tool_call: ")+g.content);
        messages.push_back(std::string("tool_observation_untrusted: ")+ObservationJson(obs));
    }
    r.error="INTERNAL_LOOP_ERROR";return r;
}
} // namespace rawrxd::deep2
