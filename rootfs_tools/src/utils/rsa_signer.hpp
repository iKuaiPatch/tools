#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// RSA / SHA-256 / PKCS#1 sign+verify utility.
// Accepts PEM or DER key files.
// If no public key is configured, verification falls back to the private key.
class RsaSigner {
public:
    RsaSigner() = default;

    void set_private_key_file(const char *path) { private_key_file_ = path ? path : ""; }
    void set_public_key_file (const char *path) { public_key_file_  = path ? path : ""; }

    bool has_private_key() const { return !private_key_file_.empty(); }
    bool has_any_key()     const { return !private_key_file_.empty() || !public_key_file_.empty(); }

    // Sign data[0..size). Writes exactly sig_capacity bytes to sig.
    // Returns 0 on success, -1 on failure.
    int sign  (const uint8_t *data, size_t size,
               uint8_t *sig, size_t sig_capacity) const;

    // Verify sig against data[0..size).
    // Returns 0 (pass), -1 (fail).
    // If no key is configured, emits a warning and returns 0 (skip).
    int verify(const uint8_t *data, size_t size,
               const uint8_t *sig,  size_t sig_size) const;

private:
    std::string private_key_file_;
    std::string public_key_file_;

    void *load_public_key ()      const;   // returns EVP_PKEY*
    void *load_private_key()      const;   // returns EVP_PKEY*
    void *load_verification_key() const;   // public key if set, else private key

    static int  do_sign  (void *pkey, const uint8_t *data, size_t size,
                          uint8_t *sig, size_t sig_capacity);
    static int  do_verify(void *pkey, const uint8_t *data, size_t size,
                          const uint8_t *sig, size_t sig_size);
    static void print_ssl_error(const char *prefix);
};
