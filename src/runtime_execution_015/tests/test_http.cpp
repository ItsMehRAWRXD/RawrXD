#include "http.hpp"
#include <cassert>
#include <iostream>
int main(){rawr::HttpResponse r;
 assert(rawr::parse_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",r)&&r.status==200&&r.body=="{}");
 assert(!rawr::parse_response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",r));
 assert(!rawr::parse_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",r));
 assert(!rawr::parse_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",r));
 assert(!rawr::parse_response("HTTP/1.1 two OK\r\n\r\n{}",r));
 assert(rawr::looks_like_json(" \n {\"ok\":true}"));assert(!rawr::looks_like_json("<html>"));
 assert(rawr::json_escape("\"\n") == "\\\"\\n");
 std::cout<<"parser negative cases PASS\n";
}
