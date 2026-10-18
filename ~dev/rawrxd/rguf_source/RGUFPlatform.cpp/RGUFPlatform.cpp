#include "RGUFPlatform.hpp"
#include <random>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib,"bcrypt.lib")
#endif
namespace rguf {
uint32_t crc32(const uint8_t* p,size_t n){uint32_t c=0xffffffffu;for(size_t i=0;i<n;i++){c^=p[i];for(int k=0;k<8;k++)c=(c>>1)^(0xedb88320u&-(c&1));}return ~c;}
bool random_bytes(uint8_t* p,size_t n){
#ifdef _WIN32
 if(BCryptGenRandom(nullptr,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0)return true;
#endif
 std::random_device d;for(size_t i=0;i<n;i++)p[i]=(uint8_t)d();return true;
}
#ifdef _WIN32
static bool crypt(bool enc,const uint8_t key[32],const uint8_t nonce[12],const uint8_t* in,size_t n,const uint8_t tagin[16],std::vector<uint8_t>& out,uint8_t tag[16],std::string& err){BCRYPT_ALG_HANDLE a=nullptr;BCRYPT_KEY_HANDLE k=nullptr;DWORD cb=0;if(BCryptOpenAlgorithmProvider(&a,BCRYPT_AES_ALGORITHM,nullptr,0)!=0){err="BCryptOpenAlgorithmProvider";return false;}if(BCryptSetProperty(a,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0)!=0){err="BCryptSetProperty";BCryptCloseAlgorithmProvider(a,0);return false;}if(BCryptGenerateSymmetricKey(a,&k,nullptr,0,(PUCHAR)key,32,0)!=0){err="BCryptGenerateSymmetricKey";BCryptCloseAlgorithmProvider(a,0);return false;}out.resize(n);BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;BCRYPT_INIT_AUTH_MODE_INFO(ai);ai.pbNonce=(PUCHAR)nonce;ai.cbNonce=12;ai.pbTag=enc?tag:(PUCHAR)tagin;ai.cbTag=16;NTSTATUS s=enc?BCryptEncrypt(k,(PUCHAR)in,(ULONG)n,&ai,nullptr,0,nullptr,0,&cb,0):BCryptDecrypt(k,(PUCHAR)in,(ULONG)n,&ai,nullptr,0,nullptr,0,&cb,0);if(s!=0){err="BCrypt size/validation";BCryptDestroyKey(k);BCryptCloseAlgorithmProvider(a,0);return false;}out.resize(cb);s=enc?BCryptEncrypt(k,(PUCHAR)in,(ULONG)n,&ai,nullptr,0,out.data(),(ULONG)out.size(),&cb,0):BCryptDecrypt(k,(PUCHAR)in,(ULONG)n,&ai,nullptr,0,out.data(),(ULONG)out.size(),&cb,0);if(s!=0){err="BCrypt crypt/authentication failed";out.clear();BCryptDestroyKey(k);BCryptCloseAlgorithmProvider(a,0);return false;}out.resize(cb);BCryptDestroyKey(k);BCryptCloseAlgorithmProvider(a,0);return true;}
#endif
bool aes256gcm_encrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t* in,size_t n,std::vector<uint8_t>& out,uint8_t tag[16],std::string& err){
#ifdef _WIN32
 return crypt(true,key,nonce,in,n,nullptr,out,tag,err);
#else
 (void)key;(void)nonce;(void)in;(void)n;(void)out;(void)tag;err="AES-GCM requires Windows CNG in this zero-dependency build";return false;
#endif
}
bool aes256gcm_decrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t* in,size_t n,const uint8_t tag[16],std::vector<uint8_t>& out,std::string& err){
#ifdef _WIN32
 uint8_t dummy[16]{};return crypt(false,key,nonce,in,n,tag,out,dummy,err);
#else
 (void)key;(void)nonce;(void)in;(void)n;(void)tag;(void)out;err="AES-GCM requires Windows CNG in this zero-dependency build";return false;
#endif
}
}
