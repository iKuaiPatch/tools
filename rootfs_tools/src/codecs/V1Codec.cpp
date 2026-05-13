#include "V1Codec.hpp"
#include "common.hpp"
#include "utils/logger.hpp"
#include <cstring>

// ---------------------------------------------------------------------------
// File-scope lookup tables
// ---------------------------------------------------------------------------

const uint8_t V1Codec::HASH_TABLE[64] = {
    0x00, 0x00, 0x00, 0x00, 0x64, 0x10, 0xB7, 0x1D, 0xC8, 0x20, 0x6E, 0x3B, 0xAC, 0x30, 0xD9, 0x26,
    0x90, 0x41, 0xDC, 0x76, 0xF4, 0x51, 0x6B, 0x6B, 0x58, 0x61, 0xB2, 0x4D, 0x3C, 0x71, 0x05, 0x50,
    0x20, 0x83, 0xB8, 0xED, 0x44, 0x93, 0x0F, 0xF0, 0xE8, 0xA3, 0xD6, 0xD6, 0x8C, 0xB3, 0x61, 0xCB,
    0xB0, 0xC2, 0x64, 0x9B, 0xD4, 0xD2, 0xD3, 0x86, 0x78, 0xE2, 0x0A, 0xA0, 0x1C, 0xF2, 0xBD, 0xBD
};

// ---------------------------------------------------------------------------
// Class-static data
// ---------------------------------------------------------------------------

const uint8_t V1Codec::KEY[16] = {
    0x77, 0xb1, 0xfa, 0x93, 0x74, 0x2c, 0xb3, 0x9d,
    0x33, 0x83, 0x55, 0x3e, 0x84, 0x8a, 0x52, 0x91
};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

static uint32_t swap_bytes(uint32_t val) {
    return ((val << 24) & 0xFF000000u) |
           ((val <<  8) & 0x00FF0000u) |
           ((val >>  8) & 0x0000FF00u) |
           ((val >> 24) & 0x000000FFu);
}

static uint32_t hash_raw(const uint8_t *data, size_t length, const uint32_t *words) {
    size_t   i      = 0;
    uint32_t result = 0xffffffffu;
    while (length != i) {
        uint8_t  cur = data[i++];
        uint32_t tmp = words[(cur ^ static_cast<uint8_t>(result)) & 0xf] ^ (result >> 4);
        result       = words[(static_cast<uint8_t>(tmp) ^ (cur >> 4)) & 0xf] ^ (tmp >> 4);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Static protected methods
// ---------------------------------------------------------------------------

uint8_t V1Codec::rotl8(uint8_t v, uint8_t s) {
    return static_cast<uint8_t>((v << s) | (v >> (8 - s)));
}

uint8_t V1Codec::rotr8(uint8_t v, uint8_t s) {
    return static_cast<uint8_t>((v >> s) | (v << (8 - s)));
}

uint32_t V1Codec::get_hash(const uint8_t *data, size_t length) const {
    const uint32_t *words = reinterpret_cast<const uint32_t *>(get_hash_table());
    uint32_t h = hash_raw(data, length, words);
    h = (~h) & 0xffffffffu;
    h = swap_bytes(h);
    uint8_t hb[4];
    memcpy(hb, &h, 4);
    h = hash_raw(hb, 4, words);
    h = (~h) & 0xffffffffu;
    h = swap_bytes(h);
    return h;
}

void V1Codec::generate_extended_key(const uint8_t *base_key, uint8_t *ext_key) {
    for (int i = 0; i < 1024; i++) {
        uint32_t val = base_key[i & 0xf]
                     + static_cast<uint32_t>(19916032) * static_cast<uint32_t>(i + 1) / 131u;
        ext_key[i] = static_cast<uint8_t>(val);
    }
}

// ---------------------------------------------------------------------------
// Shared byte-transform primitives (used by V1 and V2; V3 has its own cipher)
// ---------------------------------------------------------------------------

void V1Codec::apply_encode_transform(uint8_t *data, size_t data_size, const uint8_t *ext_key) {
    int8_t size_low = static_cast<int8_t>(data_size);
    for (size_t iter = data_size; iter > 0; iter--) {
        uint8_t lb     = static_cast<uint8_t>(size_low + ext_key[(iter - 1) % 1024]);
        uint8_t cur    = data[iter - 1];
        uint8_t shift  = (lb % 7) + 1;
        uint8_t rot    = static_cast<uint8_t>((cur >> shift) | (cur << (8 - shift)));
        data[iter - 1] = static_cast<uint8_t>(rot + lb);
    }
}

void V1Codec::apply_decode_transform(uint8_t *data, size_t data_size, const uint8_t *ext_key) {
    int8_t size_low = static_cast<int8_t>(data_size);
    for (size_t iter = 0; iter < data_size; iter++) {
        uint8_t lb    = static_cast<uint8_t>(size_low + ext_key[iter % 1024]);
        uint8_t cur   = data[iter];
        uint8_t diff  = static_cast<uint8_t>(cur - lb);
        uint8_t shift = (lb % 7) + 1;
        data[iter]    = static_cast<uint8_t>((diff << shift) | (diff >> (8 - shift)));
    }
}

// ---------------------------------------------------------------------------
// V1 encrypt / decrypt
// ---------------------------------------------------------------------------

int V1Codec::encrypt(uint8_t *data, size_t *data_size,
                    const uint8_t *key, const uint8_t * /*signature*/) {
    size_t original_size = *data_size;
    if (original_size < 1) {
        Log::error("File is empty");
        return -1;
    }

    const uint8_t *use_key = key ? key : KEY;
    uint8_t ext_key[1024];
    generate_extended_key(use_key, ext_key);

    uint32_t calculated_hash = get_hash(data, original_size);
    apply_encode_transform(data, original_size, ext_key);
    memcpy(data + original_size, &calculated_hash, 4);
    *data_size = original_size + 4;

    Log::info("Encrypted data size: " SIZE_T_FMT, *data_size);
    return 0;
}

int V1Codec::decrypt(uint8_t *data, size_t *data_size,
                    uint8_t *key, uint8_t * /*signature*/) {
    size_t file_size = *data_size;
    if (file_size < 4) {
        Log::error("File too small (less than 4 bytes)");
        return -1;
    }

    uint32_t authentic_hash;
    memcpy(&authentic_hash, data + file_size - 4, 4);

    size_t actual_size = file_size - 4;
    if (key) memcpy(key, KEY, 16);
    if (Log::is_debug()) Log::hexdump("Extracted Key", KEY, 16);

    uint8_t ext_key[1024];
    generate_extended_key(KEY, ext_key);
    apply_decode_transform(data, actual_size, ext_key);

    uint32_t calculated_hash = get_hash(data, actual_size);
    if (calculated_hash != authentic_hash) {
        Log::error("Hash verification failed!");
        Log::error("  Calculated: 0x%08x", calculated_hash);
        Log::error("  Authentic:  0x%08x", authentic_hash);
        return -1;
    }
    Log::info("Hash verification: PASSED");
    if (Log::is_debug()) {
        Log::debug("  Calculated: 0x%08x", calculated_hash);
        Log::debug("  Authentic:  0x%08x", authentic_hash);
    }

    *data_size = actual_size;
    return 0;
}
