#pragma once
#include <string>
#include <string_view>
#include <optional>
#include <cctype>
#include <limits>
namespace rawr {
struct HttpResponse { int status=0; std::string body; std::string error; };
inline bool parse_response(std::string_view wire, HttpResponse& out) {
  out={};
  auto first=wire.find("\r\n"); if(first==std::string_view::npos){out.error="missing status line";return false;}
  auto line=wire.substr(0,first); if(line.substr(0,5)!="HTTP/"){out.error="bad protocol";return false;}
  auto space=line.find(' '); if(space==std::string_view::npos || space+4>line.size()){out.error="missing status";return false;}
  for(int i=1;i<=3;i++) if(!std::isdigit(static_cast<unsigned char>(line[space+i]))){out.error="non numeric status";return false;}
  if(space+4<line.size() && line[space+4]!=' '){out.error="bad status separator";return false;}
  out.status=(line[space+1]-'0')*100+(line[space+2]-'0')*10+(line[space+3]-'0');
  auto end=wire.find("\r\n\r\n");if(end==std::string_view::npos){out.error="missing headers terminator";return false;}
  bool lengthFound=false;size_t contentLength=0;bool chunked=false;
  auto start=first+2;
  while(start<end){auto stop=wire.find("\r\n",start);if(stop==std::string_view::npos||stop>end){out.error="bad header";return false;}
    auto h=wire.substr(start,stop-start);auto colon=h.find(':');if(colon==std::string_view::npos){out.error="bad header field";return false;}
    std::string key(h.substr(0,colon));for(auto& c:key)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto v=h.substr(colon+1);while(!v.empty()&&(v.front()==' '||v.front()=='\t'))v.remove_prefix(1);
    if(key=="transfer-encoding"){std::string value(v);for(auto&c:value)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));if(value.find("chunked")!=std::string::npos)chunked=true;}
    if(key=="content-length") {if(lengthFound){out.error="duplicate length";return false;}lengthFound=true;if(v.empty()){out.error="empty length";return false;}
      for(char c:v){if(c<'0'||c>'9'||contentLength>(std::numeric_limits<size_t>::max()-static_cast<size_t>(c-'0'))/10){out.error="bad length";return false;}contentLength=contentLength*10+static_cast<size_t>(c-'0');}}
    start=stop+2;
  }
  if(chunked){out.error="chunked not supported (fail closed)";return false;}
  auto body=wire.substr(end+4);if(lengthFound&&body.size()!=contentLength){out.error="body length mismatch";return false;}
  out.body=std::string(body);return true;
}
inline bool looks_like_json(std::string_view s){auto i=s.find_first_not_of(" \t\r\n");return i!=std::string_view::npos&&(s[i]=='{'||s[i]=='[');}
inline std::string json_escape(std::string_view s){std::string v;for(unsigned char c:s){switch(c){case '"':v+="\\\"";break;case '\\':v+="\\\\";break;case '\n':v+="\\n";break;case '\r':v+="\\r";break;case '\t':v+="\\t";break;default: if(c<32){const char* hex="0123456789abcdef";v+="\\u00";v+=hex[c>>4];v+=hex[c&15];}else v+=static_cast<char>(c);}}return v;}
}
