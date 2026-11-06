#include "../src/core/extension_read_policy.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
using rawrxd::extensions::readExactly;
int main() {
 int failures=0; auto check=[&](bool b,const char* n){std::cout<<(b?"PASS ":"FAIL ")<<n<<'\n';if(!b)++failures;};
 char buffer[16]{};
 check(readExactly(buffer,0,[](char*,std::size_t){return std::size_t(0);}),"empty file");
 check(readExactly(buffer,5,[](char* p,std::size_t n){std::memcpy(p,"hello",n);return n;}) && std::string(buffer,5)=="hello","full read");
 std::memset(buffer,0,sizeof buffer); int calls=0;
 check(readExactly(buffer,5,[&](char* p,std::size_t n){++calls;auto m=std::min<std::size_t>(n,2);std::memcpy(p,"hello"+((calls-1)*2),m);return m;}) && std::string(buffer,5)=="hello" && calls==3,"short reads retried");
 check(!readExactly(buffer,5,[](char*,std::size_t){return std::size_t(0);}),"premature EOF");
 check(!readExactly(buffer,5,[](char*,std::size_t n){return n+1;}),"overreport rejected");
 check(!readExactly(nullptr,1,[](char*,std::size_t){return std::size_t(1);}),"null buffer rejected");
 check(!readExactly(buffer,5,[](char* p,std::size_t n){p[0]='x';return n+1;}),"overreported bytes rejected after write");
 int attempt=0;
 check(!readExactly(buffer,5,[&](char* p,std::size_t){++attempt;if(attempt==1){p[0]='a';return std::size_t(1);}return std::size_t(0);}) && attempt==2,"partial then EOF rejected");
 attempt=0;
 check(!readExactly(buffer,5,[&](char* p,std::size_t n){++attempt;if(attempt==1){p[0]='a';return std::size_t(1);}return n+1;}) && attempt==2,"partial then overreport rejected");
 check(readExactly(nullptr,0,[](char*,std::size_t){return std::size_t(1);}),"zero length null buffer accepted");
 check(readExactly(buffer,5,[](char* p,std::size_t n){std::memset(p,'z',n);return n;}) && std::string(buffer,5)=="zzzzz","buffer overwritten exactly");
 std::string written;
 check(writeExactly("abcde",5,[&](const char* p,std::size_t n){written.append(p,n);return n;}) && written=="abcde","full write");
 written.clear();
 check(writeExactly("abcde",5,[&](const char* p,std::size_t n){const auto k=std::min<std::size_t>(n,2);written.append(p,k);return k;}) && written=="abcde","short writes retried");
 check(!writeExactly("abcde",5,[](const char*,std::size_t){return std::size_t(0);}),"failed write rejected");
 check(!writeExactly("abcde",5,[](const char*,std::size_t n){return n+1;}),"overreported write rejected");
 check(!writeExactly(nullptr,1,[](const char*,std::size_t){return std::size_t(1);}),"null write buffer rejected");
 check(writeExactly(nullptr,0,[](const char*,std::size_t){return std::size_t(0);}),"empty write accepted");
 std::cout<<"RESULT "<<(failures?"FAIL":"PASS")<<" failures="<<failures<<'\n';return failures?1:0;
}
