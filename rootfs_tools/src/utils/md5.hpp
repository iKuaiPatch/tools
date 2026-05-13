#pragma once
#include <cstdint>
#include <cstddef>

struct MD5Context {
    uint64_t size;
    uint32_t buffer[4];
    uint8_t  input[64];
    uint8_t  digest[16];
};

void md5Init(MD5Context *ctx);
void md5Update(MD5Context *ctx, const uint8_t *input, size_t input_len);
void md5Finalize(MD5Context *ctx);
void md5Step(uint32_t *buffer, uint32_t *input);
