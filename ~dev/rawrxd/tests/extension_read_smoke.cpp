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
 std::cout<<"RESULT "<<(failures?"FAIL":"PASS")<<" failures="<<failures<<'\n';return failures?1:0;
}
