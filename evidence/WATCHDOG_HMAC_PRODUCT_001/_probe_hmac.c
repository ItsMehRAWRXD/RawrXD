#include <stdio.h>
#include <string.h>
#include <windows.h>
extern int asm_camellia256_self_test(void);
extern int asm_camellia256_set_key(const unsigned char*);
extern int asm_camellia256_get_hmac_key(unsigned char*);
extern int asm_camellia256_init(void);
int main(void){
  unsigned char k[32]; int i,rc;
  for(i=0;i<32;i++) k[i]=(unsigned char)(0xA5^i);
  printf("self_test=%d\n", asm_camellia256_self_test()); fflush(stdout);
  printf("set_key=%d\n", asm_camellia256_set_key(k)); fflush(stdout);
  memset(k,0,32);
  rc=asm_camellia256_get_hmac_key(k);
  printf("ghk_rc=%d nz=%d first4=%02X%02X%02X%02X\n", rc, (k[0]|k[1]|k[2]|k[3]|k[4]|k[5]|k[6]|k[7])!=0, k[0],k[1],k[2],k[3]);
  fflush(stdout);
  rc=asm_camellia256_init();
  printf("init=%d\n", rc); fflush(stdout);
  memset(k,0,32);
  rc=asm_camellia256_get_hmac_key(k);
  printf("ghk2_rc=%d nz=%d first4=%02X%02X%02X%02X\n", rc, (k[0]|k[1]|k[2]|k[3]|k[4]|k[5]|k[6]|k[7])!=0, k[0],k[1],k[2],k[3]);
  return 0;
}
