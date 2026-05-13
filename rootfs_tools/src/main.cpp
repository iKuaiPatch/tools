#include "utils/registry.hpp"
#include "codecs/V1Codec.hpp"
#include "codecs/V2Codec.hpp"
#include "codecs/V3Codec.hpp"
#include "common.hpp"
#include "utils/logger.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#ifdef _WIN32
#  include <direct.h>
#  define make_dir(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define make_dir(p) mkdir((p), 0755)
#endif

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

static int read_file(const char *filename, uint8_t **data, size_t *size) {
    FILE *f = fopen(filename, "rb");
    if (!f) { Log::error("%s: %s", filename, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    *size = static_cast<size_t>(ftell(f));
    fseek(f, 0, SEEK_SET);
    // Extra space covers any trailer appended during encrypt.
    *data = static_cast<uint8_t *>(malloc(*size + 1024));
    if (!*data) {
        Log::error("Memory allocation failed");
        fclose(f);
        return -1;
    }
    if (fread(*data, 1, *size, f) != *size) {
        Log::error("Error reading %s", filename);
        free(*data);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int write_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *f = fopen(filename, "wb");
    if (!f) { Log::error("%s: %s", filename, strerror(errno)); return -1; }
    if (fwrite(data, 1, size, f) != size) {
        Log::error("Error writing %s", filename);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static char *join_path(const char *dir, const char *name) {
    size_t dl = strlen(dir), nl = strlen(name);
    char  *p  = static_cast<char *>(malloc(dl + nl + 2));
    if (!p) return nullptr;
    strcpy(p, dir);
    if (dl > 0 && dir[dl - 1] != '/' && dir[dl - 1] != '\\')
#ifdef _WIN32
        strcat(p, "\\");
#else
        strcat(p, "/");
#endif
    strcat(p, name);
    return p;
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

static void print_usage(const char *prog) {
    #define printfn(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
    printfn("Usage: %s <operation> <input_file> <output_dir|output_file> [OPTIONS]", prog);
    printfn(" ");
    printfn("Operations:");
    printfn("  decrypt       Decrypt rootfs");
    printfn("  encrypt       Encrypt rootfs");
    printfn(" ");
    printfn("Options:");
    printfn("  -v1                Use v1 rootfs format (default)");
    printfn("  -v2                Use v2 rootfs format");
    printfn("  -v3                Use v3 rootfs format");
    printfn("  -d                 Enable debug output");
    printfn("  -l LENGTH          Rootfs length (split off trailing data)");
    printfn("  -a APPEND_FILE     File to append after encrypt");
    printfn("  -k KEY_FILE        Reuse 16-byte key/seed for byte-exact encrypt");
    printfn("  -p PRIVATE_KEY     V3 private key (signing / verification)");
    printfn("  -s SIGNATURE_FILE  Pre-built signature file for V3 encrypt");
    printfn("  -u PUBLIC_KEY      Override V3 RSA public key for verification");
    printfn("  -h                 Show this help");
    printfn(" ");
    printfn("Examples:");
    printfn("  %s decrypt rootfs          output_dir", prog);
    printfn("  %s decrypt rootfs          output_dir  -v2", prog);
    printfn("  %s decrypt rootfs          output_dir  -v3 -p private.pem", prog);
    printfn("  %s encrypt rootfs.img.xz   output.img", prog);
    printfn("  %s encrypt rootfs.img.xz   output.img  -v2 -k key.bin", prog);
    printfn("  %s encrypt rootfs.img.xz   output.img  -v3 -k key.bin -p private.pem", prog);
    #undef printfn
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    // ---- Register codecs ----
    CodecRegistry &reg = CodecRegistry::instance();
    reg.register_codec(new V1Codec());
    reg.register_codec(new V2Codec());
    reg.register_codec(new V3Codec());

    if (argc < 4) { print_usage(argv[0]); return 1; }

    const char *operation   = argv[1];
    const char *input_file  = argv[2];
    const char *output_path = argv[3];

    // ---- Option defaults ----
    RootfsFormat format           = RootfsFormat::V1;
    bool        debug_flag       = false;
    bool        is_encrypt       = false;
    bool        is_decrypt       = false;
    size_t      end_length       = 0;
    bool        has_end_length   = false;
    const char *append_file      = nullptr;
    const char *key_file         = nullptr;
    const char *private_key_file = nullptr;
    const char *public_key_file  = nullptr;
    const char *signature_file   = nullptr;

    // ---- Parse options ----
    for (int i = 4; i < argc; i++) {
        if      (strcmp(argv[i], "-v1") == 0) { format = RootfsFormat::V1; }
        else if (strcmp(argv[i], "-v2") == 0) { format = RootfsFormat::V2; }
        else if (strcmp(argv[i], "-v3") == 0) { format = RootfsFormat::V3; }
        else if (strcmp(argv[i], "-d")  == 0) { debug_flag = true; }
        else if (strcmp(argv[i], "-h")  == 0) { print_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-l")  == 0 && i + 1 < argc) {
            end_length = static_cast<size_t>(strtoul(argv[++i], nullptr, 10));
            has_end_length = true;
        }
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) { append_file = argv[++i]; }
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { key_file    = argv[++i]; }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) { private_key_file = argv[++i]; }
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) { signature_file   = argv[++i]; }
        else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) { public_key_file  = argv[++i]; }
        else if (strcmp(operation, "encrypt") == 0 && !append_file && argv[i][0] != '-') {
            append_file = argv[i];
        }
        else {
            Log::error("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    is_encrypt = (strcmp(operation, "encrypt") == 0);
    is_decrypt = (strcmp(operation, "decrypt") == 0);

    if (!is_encrypt && !is_decrypt) {
        Log::error("Invalid operation '%s'. Must be encrypt or decrypt.", operation);
        return 1;
    }

    // ---- Validate option combinations ----
    if (signature_file && (!is_encrypt || format != RootfsFormat::V3)) {
        Log::error("-s is only valid for v3 encrypt"); return 1; }
    if (private_key_file && format != RootfsFormat::V3) {
        Log::error("-p is only valid for -v3"); return 1; }
    if (public_key_file && format != RootfsFormat::V3) {
        Log::error("-u is only valid for -v3"); return 1; }
    if (key_file && !is_encrypt) {
        Log::error("-k is only valid for encrypt"); return 1; }
    if (signature_file && private_key_file) {
        Log::error("-s and -p cannot be used together"); return 1; }
    if (is_encrypt && format == RootfsFormat::V3 && !signature_file && !private_key_file) {
        Log::error("V3 encrypt requires -s SIGNATURE_FILE or -p PRIVATE_KEY_FILE");
        return 1;
    }

    // ---- Configure global debug flag ----
    Log::set_debug(debug_flag);

    // ---- Get and configure codec ----
    RootfsCodec *codec = reg.get(format);
    if (!codec) { Log::error("No codec registered for format %d", static_cast<int>(format)); return 1; }

    if (format == RootfsFormat::V3) {
        V3Codec *v3 = dynamic_cast<V3Codec *>(codec);
        if (v3) {
            v3->set_private_key_file(private_key_file);
            v3->set_public_key_file(public_key_file);
        }
    }

    // ---- Read input ----
    uint8_t *data     = nullptr;
    size_t   data_size = 0;
    if (read_file(input_file, &data, &data_size) != 0) return 1;

    // ---- Load optional key (16 bytes, used by all format versions) ----
    uint8_t provided_key[RootfsCodec::KEY_SIZE] = {};
    bool    has_provided_key = false;
    if (key_file) {
        uint8_t *kd = nullptr; size_t ks = 0;
        if (read_file(key_file, &kd, &ks) != 0) { free(data); return 1; }
        if (ks != static_cast<size_t>(RootfsCodec::KEY_SIZE)) {
            Log::error("Key file must be %d bytes", RootfsCodec::KEY_SIZE);
            free(kd); free(data); return 1;
        }
        memcpy(provided_key, kd, RootfsCodec::KEY_SIZE);
        has_provided_key = true;
        free(kd);
    }

    // ---- Load optional signature ----
    uint8_t provided_sig[V3Codec::SIGNATURE_SIZE] = {};
    bool    has_provided_sig = false;
    if (signature_file) {
        uint8_t *sd = nullptr; size_t ss = 0;
        if (read_file(signature_file, &sd, &ss) != 0) { free(data); return 1; }
        if (ss != static_cast<size_t>(V3Codec::SIGNATURE_SIZE)) {
            Log::error("Signature file must be %d bytes", V3Codec::SIGNATURE_SIZE);
            free(sd); free(data); return 1;
        }
        memcpy(provided_sig, sd, V3Codec::SIGNATURE_SIZE);
        has_provided_sig = true;
        free(sd);
    }

    // ---- Create output directory for decrypt ----
    if (is_decrypt) make_dir(output_path);

    // ---- Handle end-data split (decrypt with -l) ----
    if (is_decrypt && has_end_length && end_length < data_size) {
        size_t    end_sz  = data_size - end_length;
        uint8_t  *end_ptr = data + end_length;
        char *ep = join_path(output_path, "end.gz");
        if (ep) {
            if (write_file(ep, end_ptr, end_sz) == 0)
                Log::info("Extracted end.gz (" SIZE_T_FMT " bytes)", end_sz);
            free(ep);
        }
        data_size = end_length;
    }

    // ---- Perform encrypt / decrypt ----
    uint8_t key[RootfsCodec::KEY_SIZE]         = {};
    uint8_t signature[V3Codec::SIGNATURE_SIZE] = {};
    int result;

    if (is_encrypt) {
        const uint8_t *use_key = has_provided_key ? provided_key : nullptr;
        const uint8_t *use_sig = has_provided_sig ? provided_sig : nullptr;
        result = codec->encrypt(data, &data_size, use_key, use_sig);
    } else {
        result = codec->decrypt(data, &data_size, key,
                               format == RootfsFormat::V3 ? signature : nullptr);
    }

    if (result != 0) { free(data); return 1; }

    // ---- Save decrypt side-outputs ----
    if (is_decrypt) {
        char *kp = join_path(output_path, "key.bin");
        if (kp) { write_file(kp, key, RootfsCodec::KEY_SIZE); free(kp); }

        if (format == RootfsFormat::V3) {
            char *sp = join_path(output_path, "signature.bin");
            if (sp) { write_file(sp, signature, V3Codec::SIGNATURE_SIZE); free(sp); }
        }
    }

    // ---- Append extra file for encrypt ----
    if (is_encrypt && append_file) {
        uint8_t *ad = nullptr; size_t as = 0;
        if (read_file(append_file, &ad, &as) == 0) {
            data = static_cast<uint8_t *>(realloc(data, data_size + as));
            if (data) {
                memcpy(data + data_size, ad, as);
                data_size += as;
                Log::info("Added %s (" SIZE_T_FMT " bytes)", append_file, as);
            }
            free(ad);
        }
    }

    // ---- Write main output ----
    char *out;
    if (is_decrypt) {
        out = join_path(output_path, "rootfs.ext2");
    } else {
        out = strdup(output_path);
    }
    if (out) {
        if (write_file(out, data, data_size) == 0)
            Log::info("%s completed successfully: %s", operation, out);
        free(out);
    }

    free(data);
    return 0;
}
