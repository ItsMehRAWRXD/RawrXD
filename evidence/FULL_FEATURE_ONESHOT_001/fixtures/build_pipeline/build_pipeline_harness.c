#include <stdio.h>
#include <string.h>
int main(int argc, char** argv){
  if(argc>1 && strcmp(argv[1],"--ping")==0){ puts("BUILD_PIPELINE_HARNESS_OK"); return 0; }
  puts("usage: build_pipeline_harness --ping");
  return 2;
}

