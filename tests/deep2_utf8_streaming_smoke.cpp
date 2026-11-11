#include "../~dev/rawrxd/src/generation/module3_utf8.h"
#include <cassert>
#include <string>
int main() {
    Utf8StreamingSanitizer s;
    assert(s.sanitize("plain ASCII") == "plain ASCII");
    assert(s.sanitize(std::string("\xE2",1)).empty());
    assert(s.sanitize(std::string("\x82",1)).empty());
    assert(s.sanitize(std::string("\xAC",1)) == std::string("\xE2\x82\xAC",3));
    assert(s.flush().empty());
    s.reset();
    assert(s.sanitize(std::string("a\0b",3)) == std::string("a\0b",3));
    assert(s.sanitize(std::string("\xC0\xAF",2)) ==
           std::string("\xEF\xBF\xBD\xEF\xBF\xBD",6));
    assert(s.sanitize(std::string("\xF4\x90\x80\x80",4)) ==
           std::string("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD",12));
    assert(s.sanitize(std::string("\xED\xA0\x80",3)) ==
           std::string("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD",9));
    assert(s.sanitize(std::string("\xE2\x82",2)).empty());
    assert(s.flush() == std::string("\xEF\xBF\xBD",3));
    assert(s.flush().empty());
    return 0;
}
