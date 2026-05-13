/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.
 * Adapted to C++ with const-correct API.
 */

#include "md5.hpp"
#include <cstring>

#define A 0x67452301u
#define B 0xefcdab89u
#define C 0x98badcfeu
#define D 0x10325476u

static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t K[] = {0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
                       0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
                       0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
                       0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
                       0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
                       0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
                       0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
                       0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
                       0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
                       0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
                       0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
                       0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
                       0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
                       0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
                       0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
                       0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

static uint32_t rotateLeft(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

void md5Init(MD5Context *ctx) {
    ctx->size      = 0;
    ctx->buffer[0] = A;
    ctx->buffer[1] = B;
    ctx->buffer[2] = C;
    ctx->buffer[3] = D;
}

void md5Update(MD5Context *ctx, const uint8_t *input_buffer, size_t input_len) {
    uint32_t input[16];
    unsigned int offset = static_cast<unsigned int>(ctx->size % 64);
    ctx->size += static_cast<uint64_t>(input_len);
    for (unsigned int i = 0; i < input_len; ++i) {
        ctx->input[offset++] = input_buffer[i];
        if (offset % 64 == 0) {
            for (unsigned int j = 0; j < 16; ++j)
                input[j] = (static_cast<uint32_t>(ctx->input[(j*4)+3]) << 24) |
                           (static_cast<uint32_t>(ctx->input[(j*4)+2]) << 16) |
                           (static_cast<uint32_t>(ctx->input[(j*4)+1]) <<  8) |
                           (static_cast<uint32_t>(ctx->input[(j*4)]));
            md5Step(ctx->buffer, input);
            offset = 0;
        }
    }
}

void md5Finalize(MD5Context *ctx) {
    uint32_t input[16];
    unsigned int offset = static_cast<unsigned int>(ctx->size % 64);
    unsigned int pad_len = offset < 56 ? 56 - offset : (56 + 64) - offset;
    md5Update(ctx, PADDING, pad_len);
    ctx->size -= static_cast<uint64_t>(pad_len);
    for (unsigned int j = 0; j < 14; ++j)
        input[j] = (static_cast<uint32_t>(ctx->input[(j*4)+3]) << 24) |
                   (static_cast<uint32_t>(ctx->input[(j*4)+2]) << 16) |
                   (static_cast<uint32_t>(ctx->input[(j*4)+1]) <<  8) |
                   (static_cast<uint32_t>(ctx->input[(j*4)]));
    input[14] = static_cast<uint32_t>(ctx->size * 8);
    input[15] = static_cast<uint32_t>((ctx->size * 8) >> 32);
    md5Step(ctx->buffer, input);
    for (unsigned int i = 0; i < 4; ++i) {
        ctx->digest[(i*4)+0] = static_cast<uint8_t>( ctx->buffer[i]        & 0xff);
        ctx->digest[(i*4)+1] = static_cast<uint8_t>((ctx->buffer[i] >>  8) & 0xff);
        ctx->digest[(i*4)+2] = static_cast<uint8_t>((ctx->buffer[i] >> 16) & 0xff);
        ctx->digest[(i*4)+3] = static_cast<uint8_t>((ctx->buffer[i] >> 24) & 0xff);
    }
}

void md5Step(uint32_t *buffer, uint32_t *input) {
    uint32_t AA = buffer[0], BB = buffer[1], CC = buffer[2], DD = buffer[3];
    uint32_t E; unsigned int j;
    for (unsigned int i = 0; i < 64; ++i) {
        switch (i / 16) {
            case 0:  E = F(BB,CC,DD); j = i;                   break;
            case 1:  E = G(BB,CC,DD); j = ((i*5)+1) % 16;      break;
            case 2:  E = H(BB,CC,DD); j = ((i*3)+5) % 16;      break;
            default: E = I(BB,CC,DD); j = (i*7)     % 16;      break;
        }
        uint32_t temp = DD; DD = CC; CC = BB;
        BB = BB + rotateLeft(AA + E + K[i] + input[j], S[i]);
        AA = temp;
    }
    buffer[0] += AA; buffer[1] += BB; buffer[2] += CC; buffer[3] += DD;
}
