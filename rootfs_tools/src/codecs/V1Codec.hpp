#pragma once
#include "RootfsCodec.hpp"

// V1Codec implements the V1 rootfs format and holds ALL legacy shared
// algorithms so V2Codec and V3Codec can reuse them via inheritance.
class V1Codec : public RootfsCodec {
public:
    static constexpr RootfsFormat FORMAT = RootfsFormat::V1;

    V1Codec() = default;

    int encrypt(uint8_t *data, size_t *data_size,
               const uint8_t *key, const uint8_t *signature) override;
    int decrypt(uint8_t *data, size_t *data_size,
               uint8_t *key, uint8_t *signature) override;
    RootfsFormat get_format() const override { return FORMAT; }

protected:
    // Hash lookup table for V1 format.
    static const uint8_t HASH_TABLE[64];

    // Returns the hash table for this format version.
    virtual const uint8_t *get_hash_table() const { return HASH_TABLE; }

    // Legacy shared primitives reused by V2 and V3.
    static uint8_t rotl8(uint8_t value, uint8_t shift);
    static uint8_t rotr8(uint8_t value, uint8_t shift);
    uint32_t       get_hash(const uint8_t *data, size_t length) const;
    static void    generate_extended_key(const uint8_t *base_key, uint8_t *ext_key);

    // Core byte-transform primitives shared by all versions.
    static void apply_encode_transform(uint8_t *data, size_t data_size, const uint8_t *ext_key);
    static void apply_decode_transform(uint8_t *data, size_t data_size, const uint8_t *ext_key);

    static const uint8_t KEY[16];
};
