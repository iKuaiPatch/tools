#include "md5.hpp"
#include <cstring>
#include <stdexcept>

void MD5Init(MD5Context* ctx) {
    ctx->ctx = EVP_MD_CTX_new();
    if (ctx->ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(ctx->ctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = nullptr;
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
}

void MD5Update(MD5Context* ctx, const void* data, std::size_t len) {
    if (EVP_DigestUpdate(ctx->ctx, data, len) != 1) {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
}

void MD5Final(MD5Context* ctx) {
    unsigned int len = 0;

    if (EVP_DigestFinal_ex(ctx->ctx, ctx->digest, &len) != 1 || len != 16) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = nullptr;
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx->ctx);
    ctx->ctx = nullptr;
}

void MD5Sum(const uint8_t* data, std::size_t data_len, uint8_t* digest) {
    MD5Context ctx;

    try {
        MD5Init(&ctx);
        MD5Update(&ctx, data, data_len);
        MD5Final(&ctx);
        std::memcpy(digest, ctx.digest, 16);
    } catch (...) {
        if (ctx.ctx != nullptr) {
            EVP_MD_CTX_free(ctx.ctx);
            ctx.ctx = nullptr;
        }
        throw;
    }
}