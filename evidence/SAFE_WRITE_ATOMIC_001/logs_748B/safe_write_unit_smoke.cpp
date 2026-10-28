#include <string>
#include <cstdio>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../../../src/win32app/SafeWriteAtomic.hpp"
bool AgentSessionNoteWrite(const std::string&, const std::string&, const std::string&) { return true; }
std::string AgentSessionReviewFirst() { return {}; }
int main(){
  std::string path = "unit_atomic.txt";
  DeleteFileA(path.c_str());
  auto wr = RawrXD::SafeWrite::WriteWithPreviewRollback(path, "unit-v1");
  printf("WRITE1 ok=%d atomic=%d previewed=%d id=%llu\n", wr.ok?1:0, wr.atomic?1:0, wr.previewed?1:0, (unsigned long long)wr.rollbackId);
  printf("STATUS=%s\n", RawrXD::SafeWrite::StatusJson().c_str());
  wr = RawrXD::SafeWrite::WriteWithPreviewRollback(path, "unit-v2");
  std::string err; bool rb=RawrXD::SafeWrite::RollbackLastWrite(err);
  char buf[64]={}; FILE* f=fopen(path.c_str(),"rb"); if(f){fread(buf,1,63,f);fclose(f);} 
  printf("ROLLBACK ok=%d CONTENT=%s\n", rb?1:0, buf);
  printf("UNIT_RUNTIME=1 PROMOTE=0\n");
  return (rb && buf[0]) ? 0 : 1;
}
