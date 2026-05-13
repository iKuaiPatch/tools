#pragma once
#include "V2Codec.hpp"
#include "utils/rsa_signer.hpp"

// V3Codec extends V2Codec.
// Uses a completely different multi-round permutation cipher with an
// RSA-signed trailer. Inherits rotl8/rotr8/get_hash from V1Codec.
// generate_v3_context is the only V3-specific context derivation algorithm.
class V3Codec : public V2Codec {
public:
    static constexpr RootfsFormat FORMAT         = RootfsFormat::V3;
    static constexpr int          KEY_SIZE       = 16;
    static constexpr int          HASH_SIZE      = 4;
    static constexpr int          SIGNATURE_SIZE = 256;
    static constexpr int          TRAILER_SIZE   = KEY_SIZE + HASH_SIZE + SIGNATURE_SIZE;
    static constexpr int          EXT_KEY_SIZE   = 2048;
    static constexpr int          PERM_SIZE      = 256;
    static constexpr int          ROUNDS         = 3;

    int encrypt(uint8_t *data, size_t *data_size,
               const uint8_t *seed, const uint8_t *signature) override;
    int decrypt(uint8_t *data, size_t *data_size,
               uint8_t *seed, uint8_t *signature) override;
    RootfsFormat get_format() const override { return FORMAT; }

    void set_private_key_file(const char *path) { signer_.set_private_key_file(path); }
    void set_public_key_file (const char *path) { signer_.set_public_key_file(path);  }

    static void generate_random_key(uint8_t *key);

protected:
    static void generate_v3_context(const uint8_t *seed,
                                    uint8_t *ext_key,
                                    uint8_t *perm,
                                    uint8_t *inv_perm);

    int verify_v3_signature(const uint8_t *data, size_t file_size) const;
    int sign_v3_signature  (const uint8_t *data, size_t signed_size, uint8_t *sig) const;

private:
    RsaSigner signer_;
};
