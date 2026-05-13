#pragma once
#include "V1Codec.hpp"

// V2Codec extends V1Codec.
// Differences from V1:
//   - Key is derived from data MD5 + CRC32 rather than the fixed default key.
//   - Appends the 16-byte key to the trailer (20 bytes total: key + hash).
//   - Uses the V2 hash table (different constants from V1).
//   - The core byte-transform (apply_encode/decode_transform) is inherited
//     from V1Codec.
class V2Codec : public V1Codec {
public:
    static constexpr RootfsFormat FORMAT       = RootfsFormat::V2;
    static constexpr int          KEY_SIZE     = 16;
    static constexpr int          HASH_SIZE    = 4;
    static constexpr int          TRAILER_SIZE = KEY_SIZE + HASH_SIZE;

    V2Codec() = default;

    int encrypt(uint8_t *data, size_t *data_size,
               const uint8_t *key, const uint8_t *signature) override;
    int decrypt(uint8_t *data, size_t *data_size,
               uint8_t *key, uint8_t *signature) override;
    RootfsFormat get_format() const override { return FORMAT; }

protected:
    // Hash lookup table for V2/V3 format.
    static const uint8_t HASH_TABLE[64];

    const uint8_t *get_hash_table() const override { return HASH_TABLE; }

    void generate_v2_key(uint8_t *out_key, const uint8_t *data, size_t length) const;
};
