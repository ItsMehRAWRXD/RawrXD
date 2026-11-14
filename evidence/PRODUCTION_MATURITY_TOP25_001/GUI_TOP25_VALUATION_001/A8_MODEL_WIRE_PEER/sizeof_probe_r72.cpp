#include <cstdio>
#include <cstddef>
#include "Deep2Engine.h"
#include "lavapath/ProductRuntime.hpp"
int main() {
  using RT = rawr::product_run::ProductRuntime;
  std::printf("SIZEOF_DEEP2ENGINE=0x%zX\n", sizeof(Deep2::Deep2Engine));
  std::printf("OFFSETOF_EXT=0x%zX\n", offsetof(RT, ext));
  std::printf("SIZEOF_PRODUCTRUNTIME=0x%zX\n", sizeof(RT));
  return 0;
}
