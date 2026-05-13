#include "rsa_signer.hpp"
#include "logger.hpp"
#include <cerrno>
#include <cstring>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// ---------------------------------------------------------------------------
// Internal helpers (file-scope)
// ---------------------------------------------------------------------------

static bool read_file_to_vec(const std::string &path, std::vector<uint8_t> &buf) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) { Log::error("%s: %s", path.c_str(), strerror(errno)); return false; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return false; }
    buf.resize(static_cast<size_t>(sz));
    bool ok = fread(buf.data(), 1, buf.size(), f) == buf.size();
    fclose(f);
    return ok;
}

static EVP_PKEY *pkey_from_mem_pubkey(const uint8_t *data, size_t size) {
    BIO *bio = BIO_new_mem_buf(data, static_cast<int>(size));
    if (!bio) return nullptr;
    EVP_PKEY *pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pk) return pk;
    const unsigned char *cursor = data;
    return d2i_PUBKEY(nullptr, &cursor, static_cast<long>(size));
}

static EVP_PKEY *pkey_from_mem_privkey(const uint8_t *data, size_t size) {
    BIO *bio = BIO_new_mem_buf(data, static_cast<int>(size));
    if (!bio) return nullptr;
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pk) return pk;
    const unsigned char *cursor = data;
    return d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(size));
}

// ---------------------------------------------------------------------------
// RsaSigner private methods
// ---------------------------------------------------------------------------

void RsaSigner::print_ssl_error(const char *prefix) {
    unsigned long err = ERR_get_error();
    if (err == 0) { Log::error("%s", prefix); return; }
    Log::error("%s: %s", prefix, ERR_error_string(err, nullptr));
}

void *RsaSigner::load_public_key() const {
    if (public_key_file_.empty()) return nullptr;
    std::vector<uint8_t> buf;
    if (!read_file_to_vec(public_key_file_, buf)) return nullptr;
    return pkey_from_mem_pubkey(buf.data(), buf.size());
}

void *RsaSigner::load_private_key() const {
    if (private_key_file_.empty()) return nullptr;
    std::vector<uint8_t> buf;
    if (!read_file_to_vec(private_key_file_, buf)) return nullptr;
    return pkey_from_mem_privkey(buf.data(), buf.size());
}

void *RsaSigner::load_verification_key() const {
    return !public_key_file_.empty() ? load_public_key() : load_private_key();
}

int RsaSigner::do_verify(void *raw_pkey, const uint8_t *data, size_t size,
                          const uint8_t *sig, size_t sig_size) {
    EVP_PKEY     *pkey = static_cast<EVP_PKEY *>(raw_pkey);
    EVP_MD_CTX   *ctx  = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    int result = -1;
    if (!ctx) { print_ssl_error("EVP_MD_CTX_new failed"); goto done; }
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey) != 1) {
        print_ssl_error("EVP_DigestVerifyInit failed"); goto done; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) {
        print_ssl_error("set_rsa_padding failed"); goto done; }
    if (EVP_DigestVerifyUpdate(ctx, data, size) != 1) {
        print_ssl_error("EVP_DigestVerifyUpdate failed"); goto done; }
    result = (EVP_DigestVerifyFinal(ctx, sig, sig_size) == 1) ? 0 : -1;
    if (result != 0) ERR_clear_error();
done:
    EVP_MD_CTX_free(ctx);
    return result;
}

int RsaSigner::do_sign(void *raw_pkey, const uint8_t *data, size_t size,
                        uint8_t *sig, size_t sig_capacity) {
    EVP_PKEY     *pkey     = static_cast<EVP_PKEY *>(raw_pkey);
    EVP_MD_CTX   *ctx      = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx     = nullptr;
    size_t        sig_size = sig_capacity;
    int result = -1;

    if (static_cast<size_t>(EVP_PKEY_size(pkey)) != sig_capacity) {
        Log::error("Key produces %d-byte signature, expected %zu",
                   EVP_PKEY_size(pkey), sig_capacity);
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (!ctx) { print_ssl_error("EVP_MD_CTX_new failed"); goto done; }
    if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), nullptr, pkey) != 1) {
        print_ssl_error("EVP_DigestSignInit failed"); goto done; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) {
        print_ssl_error("set_rsa_padding failed"); goto done; }
    if (EVP_DigestSignUpdate(ctx, data, size) != 1) {
        print_ssl_error("EVP_DigestSignUpdate failed"); goto done; }
    if (EVP_DigestSignFinal(ctx, sig, &sig_size) != 1) {
        print_ssl_error("EVP_DigestSignFinal failed"); goto done; }
    if (sig_size != sig_capacity) {
        Log::error("Unexpected signature size: %zu (expected %zu)", sig_size, sig_capacity);
        goto done;
    }
    result = 0;
done:
    EVP_MD_CTX_free(ctx);
    return result;
}

// ---------------------------------------------------------------------------
// RsaSigner public API
// ---------------------------------------------------------------------------

int RsaSigner::sign(const uint8_t *data, size_t size,
                    uint8_t *sig, size_t sig_capacity) const {
    void *pkey = load_private_key();
    if (!pkey) { print_ssl_error("Failed to load private key"); return -1; }
    int r = do_sign(pkey, data, size, sig, sig_capacity);
    EVP_PKEY_free(static_cast<EVP_PKEY *>(pkey));
    return r;
}

int RsaSigner::verify(const uint8_t *data, size_t size,
                      const uint8_t *sig, size_t sig_size) const {
    if (!has_any_key()) {
        Log::warn("Signature verification: SKIPPED (no key provided)");
        return 0;
    }
    void *pkey = load_verification_key();
    if (!pkey) { print_ssl_error("Failed to load verification key"); return -1; }
    int r = do_verify(pkey, data, size, sig, sig_size);
    EVP_PKEY_free(static_cast<EVP_PKEY *>(pkey));
    if (r != 0) { Log::error("Signature verification FAILED"); return -1; }
    Log::info("Signature verification: PASSED");
    return 0;
}
