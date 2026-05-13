#include "V3Codec.hpp"
#include "common.hpp"
#include "utils/logger.hpp"
#include <cstdlib>
#include <cstring>
#include <ctime>

int V3Codec::verify_v3_signature(const uint8_t *data, size_t file_size) const {
    if (file_size < static_cast<size_t>(SIGNATURE_SIZE)) {
        Log::error("File too small for V3 signature verification");
        return -1;
    }
    size_t signed_size = file_size - SIGNATURE_SIZE;
    return signer_.verify(data, signed_size,
                          data + signed_size, SIGNATURE_SIZE);
}

int V3Codec::sign_v3_signature(const uint8_t *data, size_t signed_size, uint8_t *sig) const {
    return signer_.sign(data, signed_size, sig, SIGNATURE_SIZE);
}

void V3Codec::generate_random_key(uint8_t *key) {
#ifndef _WIN32
    FILE *ur = fopen("/dev/urandom", "rb");
    if (ur) {
        bool ok = fread(key, 1, KEY_SIZE, ur) == KEY_SIZE;
        fclose(ur);
        if (ok) return;
    }
#endif
    static bool seeded = false;
    if (!seeded) { srand(static_cast<unsigned int>(time(nullptr))); seeded = true; }
    for (int i = 0; i < KEY_SIZE; i++)
        key[i] = static_cast<uint8_t>(rand() & 0xff);
}

// ---------------------------------------------------------------------------
// V3 context derivation (V3-only logic)
// ---------------------------------------------------------------------------

void V3Codec::generate_v3_context(const uint8_t *seed,
                                   uint8_t *ext_key,
                                   uint8_t *perm,
                                   uint8_t *inv_perm) {
    for (int i = 0; i < EXT_KEY_SIZE; i++) {
        uint64_t val = seed[i & 0xf]
                     + (static_cast<uint64_t>(19916032) * static_cast<uint64_t>(i + 1)) / 131u;
        ext_key[i] = static_cast<uint8_t>(val);
    }
    for (int i = 0; i < EXT_KEY_SIZE; i++) {
        ext_key[i] ^= static_cast<uint8_t>(i + ext_key[(7 * i + 13) % EXT_KEY_SIZE]);
    }
    for (int i = 0; i < EXT_KEY_SIZE; i++) {
        uint8_t prev = ext_key[(EXT_KEY_SIZE + i - 1) % EXT_KEY_SIZE];
        uint8_t cur  = ext_key[i];
        uint8_t next = ext_key[(i + 1) % EXT_KEY_SIZE];
        ext_key[i] = static_cast<uint8_t>((prev + cur + next) ^ rotl8(cur, 1));
    }
    for (int i = 0; i < PERM_SIZE; i++) perm[i] = static_cast<uint8_t>(i);
    uint32_t j = 0;
    for (int i = 0; i < PERM_SIZE; i++) {
        j = (j + perm[i] + seed[i & 0xf]) & 0xff;
        uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
    }
    for (int i = 0; i < PERM_SIZE; i++) inv_perm[perm[i]] = static_cast<uint8_t>(i);
    for (int i = 0; i < EXT_KEY_SIZE; i++) {
        uint8_t mask = static_cast<uint8_t>(0x10u >> ((i & 3) * 8));
        ext_key[i] = static_cast<uint8_t>(mask ^ perm[ext_key[i]]);
    }
}

// ---------------------------------------------------------------------------
// V3 encrypt / decrypt
// ---------------------------------------------------------------------------

int V3Codec::encrypt(uint8_t *data, size_t *data_size,
                    const uint8_t *seed, const uint8_t *signature) {
    size_t original_size = *data_size;
    if (original_size < 1) { Log::error("File is empty"); return -1; }
    if (original_size > UINT32_MAX - static_cast<size_t>(TRAILER_SIZE)) {
        Log::error("File too large for V3 rootfs format"); return -1; }

    uint8_t generated_seed[KEY_SIZE];
    if (!seed) { generate_random_key(generated_seed); seed = generated_seed; }

    uint8_t ext_key[EXT_KEY_SIZE];
    uint8_t perm[PERM_SIZE];
    uint8_t inv_perm[PERM_SIZE];
    generate_v3_context(seed, ext_key, perm, inv_perm);

    uint32_t calculated_hash = get_hash(data, original_size);
    if (Log::is_debug()) Log::hexdump("V3 Seed", seed, KEY_SIZE);

    for (int round = 0; round < ROUNDS; round++) {
        for (uint32_t idx = 0; idx < static_cast<uint32_t>(original_size); idx++) {
            uint32_t ev    = ext_key[(17 * round + idx) % EXT_KEY_SIZE];
            uint32_t mix   = ev + static_cast<uint32_t>(original_size) + static_cast<uint32_t>(round);
            uint8_t  carry = static_cast<uint8_t>(mix >> 8);
            uint8_t  shift = static_cast<uint8_t>((mix & 7u) + 1u);
            uint8_t  val   = perm[data[idx]];
            val = static_cast<uint8_t>(val + static_cast<uint8_t>(mix + static_cast<uint32_t>(round)));
            val = rotl8(val, shift);
            val ^= carry;
            val = static_cast<uint8_t>(val + static_cast<uint8_t>(round) + carry);
            data[idx] = val;
        }
    }

    size_t signed_size = original_size + KEY_SIZE + HASH_SIZE;
    memcpy(data + original_size,                      seed,             KEY_SIZE);
    memcpy(data + original_size + KEY_SIZE, &calculated_hash, HASH_SIZE);

    uint8_t generated_sig[SIGNATURE_SIZE];
    if (!signature) {
        if (!signer_.has_private_key()) {
            Log::error("V3 encrypt requires -s SIGNATURE_FILE or -p PRIVATE_KEY_FILE");
            return -1;
        }
        if (sign_v3_signature(data, signed_size, generated_sig) != 0) return -1;
        signature = generated_sig;
    }
    memcpy(data + original_size + KEY_SIZE + HASH_SIZE,
           signature, SIGNATURE_SIZE);

    *data_size = original_size + TRAILER_SIZE;
    if (verify_v3_signature(data, *data_size) != 0) return -1;

    Log::info("Encrypted data size: " SIZE_T_FMT, *data_size);
    return 0;
}

int V3Codec::decrypt(uint8_t *data, size_t *data_size,
                    uint8_t *seed, uint8_t *signature) {
    size_t file_size = *data_size;
    if (file_size < static_cast<size_t>(TRAILER_SIZE)) {
        Log::error("File too small for V3 rootfs format"); return -1; }

    if (verify_v3_signature(data, file_size) != 0) return -1;

    size_t actual_size = file_size - TRAILER_SIZE;
    memcpy(seed, data + actual_size, KEY_SIZE);

    uint32_t authentic_hash;
    memcpy(&authentic_hash, data + actual_size + KEY_SIZE, HASH_SIZE);

    if (signature)
        memcpy(signature,
               data + actual_size + KEY_SIZE + HASH_SIZE,
               SIGNATURE_SIZE);

    if (Log::is_debug()) Log::hexdump("Extracted V3 Seed", seed, KEY_SIZE);

    uint8_t ext_key[EXT_KEY_SIZE];
    uint8_t perm[PERM_SIZE];
    uint8_t inv_perm[PERM_SIZE];
    generate_v3_context(seed, ext_key, perm, inv_perm);

    for (int round = ROUNDS - 1; round >= 0; round--) {
        for (uint32_t idx = 0; idx < static_cast<uint32_t>(actual_size); idx++) {
            uint32_t ev    = ext_key[(17 * round + idx) % EXT_KEY_SIZE];
            uint32_t mix   = ev + static_cast<uint32_t>(actual_size) + static_cast<uint32_t>(round);
            uint8_t  carry = static_cast<uint8_t>(mix >> 8);
            uint8_t  shift = static_cast<uint8_t>((mix & 7u) + 1u);
            uint8_t  val   = data[idx];
            val = static_cast<uint8_t>(val - static_cast<uint8_t>(round) - carry);
            val ^= carry;
            val = rotr8(val, shift);
            val = static_cast<uint8_t>(val - static_cast<uint8_t>(mix + static_cast<uint32_t>(round)));
            data[idx] = inv_perm[val];
        }
    }

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
