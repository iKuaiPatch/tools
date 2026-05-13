#include "V2Codec.hpp"
#include "common.hpp"
#include "utils/md5.hpp"
#include "utils/logger.hpp"
#include <cstring>

// ---------------------------------------------------------------------------
// V2 hash lookup table (introduced in this format).
// ---------------------------------------------------------------------------

const uint8_t V2Codec::HASH_TABLE[64] = {
    0x00, 0x00, 0x00, 0x00, 0x64, 0x10, 0xB7, 0x1D, 0xC8, 0x20, 0x6E, 0x3B, 0xAC, 0x30, 0xD6, 0x26,
    0x90, 0x41, 0xDE, 0x76, 0xF4, 0x51, 0x6B, 0x6B, 0x56, 0x61, 0xB2, 0x4D, 0x3C, 0x71, 0x05, 0x50,
    0x20, 0x63, 0xB8, 0xED, 0x43, 0x93, 0x0F, 0xF0, 0xE8, 0xA3, 0xD6, 0xD6, 0x8C, 0xB3, 0x61, 0xCB,
    0xB0, 0xC2, 0x64, 0x9B, 0xD4, 0xD2, 0xD4, 0x86, 0x78, 0xE2, 0x0A, 0xA0, 0x1C, 0xF2, 0xDD, 0xBD
};

void V2Codec::generate_v2_key(uint8_t *out_key, const uint8_t *data, size_t length) const {
    // Step 1: MD5 of raw data.
    uint8_t digest[16];
    MD5Sum(data, length, digest);
    if (Log::is_debug()) Log::hexdump("Rootfs MD5", digest, 16);

    // Step 2: 20-byte block = swapped-halves-of-MD5 || CRC32.
    uint32_t crc32 = get_hash(data, length);
    Log::debug("Rootfs CRC32: %08x", crc32);

    uint8_t block[20];
    memcpy(block,      digest + 8, 8);
    memcpy(block + 8,  digest,     8);
    memcpy(block + 16, &crc32,         4);
    if (Log::is_debug()) Log::hexdump("MD5 + CRC32", block, 20);

    // Step 3: MD5(block).
    uint8_t mid[16];
    MD5Sum(block, 20, mid);
    if (Log::is_debug()) Log::hexdump("Generated Key1", mid, 16);

    // Step 4: MD5(MD5(block)).
    uint8_t final_digest[16];
    MD5Sum(mid, 16, final_digest);
    if (Log::is_debug()) Log::hexdump("Generated Key2", final_digest, 16);

    memcpy(out_key, final_digest, 16);
}

int V2Codec::encrypt(uint8_t *data, size_t *data_size,
                    const uint8_t *key, const uint8_t * /*signature*/) {
    size_t original_size = *data_size;
    if (original_size < 1) {
        Log::error("File is empty");
        return -1;
    }

    uint8_t generated[KEY_SIZE];
    if (!key) {
        generate_v2_key(generated, data, original_size);
        key = generated;
    }

    uint8_t ext_key[1024];
    generate_extended_key(key, ext_key);

    uint32_t calculated_hash = get_hash(data, original_size);
    apply_encode_transform(data, original_size, ext_key);

    // Trailer layout: [key(16)] [hash(4)]
    memcpy(data + original_size, key, KEY_SIZE);
    memcpy(data + original_size + KEY_SIZE, &calculated_hash, HASH_SIZE);
    *data_size = original_size + TRAILER_SIZE;

    Log::info("Encrypted data size: " SIZE_T_FMT, *data_size);
    return 0;
}

int V2Codec::decrypt(uint8_t *data, size_t *data_size,
                    uint8_t *key, uint8_t * /*signature*/) {
    size_t file_size = *data_size;
    if (file_size < static_cast<size_t>(TRAILER_SIZE)) {
        Log::error("File too small for V2 rootfs format");
        return -1;
    }

    uint32_t authentic_hash;
    memcpy(&authentic_hash, data + file_size - HASH_SIZE, HASH_SIZE);

    uint8_t local_key[KEY_SIZE];
    memcpy(local_key, data + file_size - TRAILER_SIZE, KEY_SIZE);
    if (key) memcpy(key, local_key, KEY_SIZE);
    if (Log::is_debug()) Log::hexdump("Extracted Key", local_key, 16);

    size_t actual_size = file_size - TRAILER_SIZE;

    uint8_t ext_key[1024];
    generate_extended_key(local_key, ext_key);
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
