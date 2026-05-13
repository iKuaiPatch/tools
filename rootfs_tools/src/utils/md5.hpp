#pragma once
#include <cstdint>
#include <cstddef>
#include <openssl/evp.h>

struct MD5Context {
    EVP_MD_CTX* ctx = nullptr;
    uint8_t digest[16];
};

void MD5Init(MD5Context* ctx);
void MD5Update(MD5Context* ctx, const void* data, std::size_t len);
void MD5Final(MD5Context* ctx);
void MD5Sum(const uint8_t* data, std::size_t data_len, uint8_t* digest);