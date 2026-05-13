#pragma once
#include <cstdint>
#include <cstddef>

// Identifies the rootfs encoding format.
enum class RootfsFormat : int {
    V1 = 1,
    V2 = 2,
    V3 = 3,
};

// Pure interface. Every codec must implement encrypt, decrypt, and get_format.
// New algorithms can implement this directly and register themselves.
class RootfsCodec {
public:
    // All format versions use a 16-byte key/seed.
    static constexpr int KEY_SIZE = 16;

    virtual ~RootfsCodec() = default;

    // Encode data in-place. key == nullptr triggers auto key-generation.
    // signature is only used by V3.
    // Returns 0 on success, -1 on error.
    virtual int encrypt(uint8_t *data, size_t *data_size,
                        const uint8_t *key, const uint8_t *signature) = 0;

    // Decrypt data in-place. Fills key (and signature for V3) on success.
    // Returns 0 on success, -1 on error.
    virtual int decrypt(uint8_t *data, size_t *data_size,
                        uint8_t *key, uint8_t *signature) = 0;

    virtual RootfsFormat get_format() const = 0;
};
