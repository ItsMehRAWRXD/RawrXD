#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace rguf {
uint32_t crc32(const uint8_t*,size_t);
bool random_bytes(uint8_t*,size_t);
bool aes256gcm_encrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t* in,size_t n,std::vector<uint8_t>& out,uint8_t tag[16],std::string& err);
bool aes256gcm_decrypt(const uint8_t key[32],const uint8_t nonce[12],const uint8_t* in,size_t n,const uint8_t tag[16],std::vector<uint8_t>& out,std::string& err);
}
