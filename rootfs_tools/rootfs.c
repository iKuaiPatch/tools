#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
#include "md5.h"

#ifdef _WIN32
#include <direct.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#  define SIZE_T_FMT "%Illu"   // MSVC / MinGW
#else
#  define SIZE_T_FMT "%zu"
#endif

// Hash tables for CRC32 calculation
static const uint8_t hash_table_old[] = {
    0x00, 0x00, 0x00, 0x00, 0x64, 0x10, 0xB7, 0x1D, 0xC8, 0x20, 0x6E, 0x3B, 0xAC, 0x30, 0xD9, 0x26, 
    0x90, 0x41, 0xDC, 0x76, 0xF4, 0x51, 0x6B, 0x6B, 0x58, 0x61, 0xB2, 0x4D, 0x3C, 0x71, 0x05, 0x50, 
    0x20, 0x83, 0xB8, 0xED, 0x44, 0x93, 0x0F, 0xF0, 0xE8, 0xA3, 0xD6, 0xD6, 0x8C, 0xB3, 0x61, 0xCB, 
    0xB0, 0xC2, 0x64, 0x9B, 0xD4, 0xD2, 0xD3, 0x86, 0x78, 0xE2, 0x0A, 0xA0, 0x1C, 0xF2, 0xBD, 0xBD
};

static const uint8_t hash_table_new[] = {
    0x00, 0x00, 0x00, 0x00, 0x64, 0x10, 0xB7, 0x1D, 0xC8, 0x20, 0x6E, 0x3B, 0xAC, 0x30, 0xD6, 0x26, 
    0x90, 0x41, 0xDE, 0x76, 0xF4, 0x51, 0x6B, 0x6B, 0x56, 0x61, 0xB2, 0x4D, 0x3C, 0x71, 0x05, 0x50, 
    0x20, 0x63, 0xB8, 0xED, 0x43, 0x93, 0x0F, 0xF0, 0xE8, 0xA3, 0xD6, 0xD6, 0x8C, 0xB3, 0x61, 0xCB, 
    0xB0, 0xC2, 0x64, 0x9B, 0xD4, 0xD2, 0xD4, 0x86, 0x78, 0xE2, 0x0A, 0xA0, 0x1C, 0xF2, 0xDD, 0xBD
};

// Default key for old rootfs format
static const uint8_t default_key[] = {
    0x77, 0xb1, 0xfa, 0x93, 0x74, 0x2c, 0xb3, 0x9d,
    0x33, 0x83, 0x55, 0x3e, 0x84, 0x8a, 0x52, 0x91
};

// Function prototypes
uint32_t crc32_hash(const uint8_t *data, size_t length, int new_rootfs);
uint32_t get_rootfs_hash(const uint8_t *data, size_t length, int new_rootfs);
void generate_extended_key(const uint8_t *base_key, uint8_t *ext_key);
void generate_random_key(uint8_t *key);
int encode_rootfs(uint8_t *data, size_t *data_size, const uint8_t *key, int new_rootfs);
int decode_rootfs(uint8_t *data, size_t *data_size, uint8_t *key, int new_rootfs);
int read_file(const char *filename, uint8_t **data, size_t *size);
int write_file(const char *filename, const uint8_t *data, size_t size);
void print_usage(const char *program_name);

int debug = 0;

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')
void hexdump(unsigned char *buf, int size)
{
    int i, j;

    for (i = 0; i < size; i += 16)
    {
        printf("%08X: ", i);

        for (j = 0; j < 16; j++)
        {
            if (i + j < size)
            {
                printf("%02X ", buf[i + j]);
            }
            else
            {
                printf("   ");
            }
        }
        printf(" ");

        for (j = 0; j < 16; j++)
        {
            if (i + j < size)
            {
                printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}

// Swap bytes for endianness conversion
uint32_t swap_bytes(uint32_t val) {
    return ((val << 24) & 0xFF000000) |
           ((val << 8)  & 0x00FF0000) |
           ((val >> 8)  & 0x0000FF00) |
           ((val >> 24) & 0x000000FF);
}

int32_t hash(const uint8_t* data, uint32_t length, int new_rootfs)
{
    const uint8_t *hash_table = new_rootfs ? hash_table_new : hash_table_old;
    // 魔改版crc32
    uint64_t i = 0;
    uint32_t result = 0xffffffff;
    while (length != i) {
        uint8_t cur_byte = data[i++];
        uint32_t tmp = ((uint32_t *)hash_table)[(cur_byte ^ (uint8_t)result) & 0xf] ^ (result >> 4);
        result = ((uint32_t *)hash_table)[((uint8_t)tmp ^ (cur_byte >> 4)) & 0xf] ^ (tmp >> 4);
    }
    return result;
}

uint32_t get_rootfs_hash(const uint8_t *data, size_t length, int new_rootfs) {
    // Calculate first hash
    uint32_t calculated_hash = hash(data, length, new_rootfs);
    calculated_hash = (~calculated_hash) & 0xffffffff;
    calculated_hash = swap_bytes(calculated_hash);
    
    // Hash the hash
    uint8_t hash_bytes[4];
    memcpy(hash_bytes, &calculated_hash, 4);
    calculated_hash = hash(hash_bytes, 4, new_rootfs);
    calculated_hash = (~calculated_hash) & 0xffffffff;
    calculated_hash = swap_bytes(calculated_hash);
    
    return calculated_hash;
}

void generate_extended_key(const uint8_t *base_key, uint8_t *ext_key) {
    for (int i = 0; i < 1024; i++) {
        uint32_t val = base_key[i & 0xf] + (uint32_t)19916032  * ((int32_t)i + 1) / 131u;
        ext_key[i] = (uint8_t)val;
    }
}

void generate_key(uint8_t *key, uint8_t *data, size_t length) {
    // Key = md5(md5(md5(rootfs) + crc32))

    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, data, length);
    md5Finalize(&ctx);

    if (debug) {
        printf("Rootfs MD5: \n");
        hexdump(ctx.digest, 16);
    }

    uint8_t md5_result[20];

    uint32_t crc32 = get_rootfs_hash(data, length, 1);

    if (debug) {
        printf("Rootfs CRC32: %08x\n", crc32);
    }

    memcpy(md5_result, ctx.digest + 8, 8); // Copy last 8 bytes
    memcpy(md5_result + 8, ctx.digest, 8); // Copy first 8 bytes
    memcpy(md5_result + 16, &crc32, 4);    // Append CRC32

    if (debug) {
        printf("MD5 + CRC32: \n");
        hexdump(md5_result, 20);
    }

    md5Init(&ctx);
    md5Update(&ctx, md5_result, 20);
    md5Finalize(&ctx);

    uint8_t md5[16];
    memcpy(md5, ctx.digest, 16);

    if (debug) {
        printf("Generated Key1: \n");
        hexdump(md5, 16);
    }

    md5Init(&ctx);
    md5Update(&ctx, md5, 16);
    md5Finalize(&ctx);

    if (debug) {
        printf("Generated Key2: \n");
        hexdump(ctx.digest, 16);
    }

    memcpy(key, ctx.digest, 16);
}

int encode_rootfs(uint8_t *data, size_t *data_size, const uint8_t *key, int new_rootfs) {
    size_t original_size = *data_size;
    
    if (original_size < 1) {
        fprintf(stderr, "Error: File is empty\n");
        return -1;
    }
    
    // Generate extended key
    uint8_t ext_key[1024];
    generate_extended_key(key, ext_key);
    
    // Calculate hash for the encoded data
    uint32_t calculated_hash = get_rootfs_hash(data, original_size, new_rootfs);
    
    // Calculate parameters
    int8_t size_low_byte = (int8_t)original_size;
    
    // Encode the data (reverse of decode process)
    for (size_t iter_val = original_size; iter_val > 0; iter_val--) {
        uint32_t tmp_var = (uint32_t)(iter_val - 1);
        uint8_t new_low_byte = (uint8_t)(size_low_byte + ext_key[tmp_var % 1024]);
        tmp_var = (tmp_var & 0xffffff00) | new_low_byte;
        
        size_t target_index = iter_val - 1;
        if (target_index < original_size) {
            uint8_t current_byte = data[target_index];
            uint8_t tmp_var_byte = tmp_var & 0xff;
            uint8_t shift_amount = (tmp_var_byte % 7) + 1;
            
            // Reverse circular left shift (circular right shift)
            uint8_t rotated = (current_byte >> shift_amount) | (uint8_t)(current_byte << (8 - shift_amount));
            
            // Add instead of subtract (reverse of subtraction)
            uint8_t result = (uint8_t)(rotated + tmp_var_byte);
            data[target_index] = result;
        }
    }
    
    // Append key if new rootfs format
    if (new_rootfs) {
        memcpy(data + original_size, key, 16);
        *data_size = original_size + 16 + 4;
    } else {
        *data_size = original_size + 4;
    }
    
    // Append hash to the end
    size_t hash_offset = new_rootfs ? original_size + 16 : original_size;
    memcpy(data + hash_offset, &calculated_hash, 4);
    
    printf("Encrypt data size: " SIZE_T_FMT "\n", *data_size);
    return 0;
}

int decode_rootfs(uint8_t *data, size_t *data_size, uint8_t *key, int new_rootfs) {
    size_t file_size = *data_size;
    
    if (file_size < 4) {
        fprintf(stderr, "Error: File too small (less than 4 bytes)\n");
        return -1;
    }
    
    // Extract hash from end of file
    uint32_t authentic_hash;
    memcpy(&authentic_hash, data + file_size - 4, 4);
    
    // Extract key and adjust data size
    size_t actual_data_size;
    if (new_rootfs) {
        if (file_size < 20) {
            fprintf(stderr, "Error: File too small for new rootfs format\n");
            return -1;
        }
        memcpy(key, data + file_size - 20, 16);
        actual_data_size = file_size - 20;
    } else {
        memcpy(key, default_key, 16);
        actual_data_size = file_size - 4;
    }

    if (debug) {
        printf("Extracted Key: \n");
        hexdump(key, 16);
    }
    
    // Generate extended key
    uint8_t ext_key[1024];
    generate_extended_key(key, ext_key);
    
    // Calculate parameters
    int8_t size_low_byte = (int8_t)actual_data_size;
    
    // Decode the data
    for (size_t iter_val = 0; iter_val < actual_data_size; iter_val++) {
        uint32_t tmp_var = (uint32_t)iter_val;
        uint8_t new_low_byte = (uint8_t)(size_low_byte + ext_key[tmp_var % 1024]);
        tmp_var = (tmp_var & 0xffffff00) | new_low_byte;
        
        if (iter_val < actual_data_size) {
            uint8_t current_byte = data[iter_val];
            uint8_t tmp_var_byte = tmp_var & 0xff;
            
            // Subtract and rotate
            uint8_t diff = (uint8_t)(current_byte - tmp_var_byte);
            uint8_t shift_amount = (tmp_var_byte % 7) + 1;
            
            // Circular left shift
            uint8_t rotated = (uint8_t)(diff << shift_amount) | (diff >> (8 - shift_amount));
            data[iter_val] = rotated;
        }
    }
    
    // Verify hash
    uint32_t calculated_hash = get_rootfs_hash(data, actual_data_size, new_rootfs);
    
    if (calculated_hash != authentic_hash) {
        printf("Hash verification failed!\n");
        printf("Calculated: 0x%08x\n", calculated_hash);
        printf("Authentic:  0x%08x\n", authentic_hash);
    } else {
        printf("Hash verification: PASSED\n");
        if (debug) {
            printf("Calculated: 0x%08x\n", calculated_hash);
            printf("Authentic:  0x%08x\n", authentic_hash);
        }
    }
    
    *data_size = actual_data_size;
    return 0;
}

int read_file(const char *filename, uint8_t **data, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening input file");
        return -1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate buffer with extra space for encoding
    *data = malloc(*size + 1024);  // Extra space for key and hash
    if (!*data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return -1;
    }
    
    // Read file
    size_t bytes_read = fread(*data, 1, *size, file);
    fclose(file);
    
    if (bytes_read != *size) {
        fprintf(stderr, "Error reading file\n");
        free(*data);
        return -1;
    }
    
    return 0;
}

int write_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening output file");
        return -1;
    }
    
    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);
    
    if (bytes_written != size) {
        fprintf(stderr, "Error writing file\n");
        return -1;
    }
    
    return 0;
}


int create_directory(const char *path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

char *join_path(const char *dir, const char *filename) {
    size_t dir_len = strlen(dir);
    size_t filename_len = strlen(filename);
    char *path = malloc(dir_len + filename_len + 2);  // +2 for separator and null terminator
    
    if (!path) return NULL;
    
    strcpy(path, dir);
    if (dir_len > 0 && dir[dir_len - 1] != '/' && dir[dir_len - 1] != '\\') {
#ifdef _WIN32
        strcat(path, "\\");
#else
        strcat(path, "/");
#endif
    }
    strcat(path, filename);
    
    return path;
}


void print_usage(const char *program_name) {
    printf("Usage: %s <operation> <input_file> <output_dir|output_file> [OPTIONS]\n", program_name);
    printf("\nOperations:\n");
    printf("  decode       Decode format rootfs\n");
    printf("  encode       Encode format rootfs\n");
    printf("\nArguments:\n");
    printf("  input_file         Input rootfs file\n");
    printf("  output_dir         Output directory (decode operations)\n");
    printf("  output_file        Output file (encode operations)\n");
    printf("\nOptions:\n");
    printf("  -v2                Use new rootfs format\n");
    printf("  -d                 Debug\n");
    printf("  -l LENGTH          Rootfs length\n");
    printf("  -a APPEND_FILE     File to append (encode operations)\n");
    printf("  -h                 Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s decode rootfs output_dir -v2\n", program_name);
    printf("  %s decode rootfs output_dir -l 1048576\n", program_name);
    printf("  %s encode rootfs.img output.img -a end.img\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    char *operation = argv[1];
    char *input_file = argv[2];
    char *output_path = argv[3];
    char *append_file = NULL;
    size_t end_length = 0;
    int has_end_length = 0;
    int is_new_format = 0;
    
    // Parse optional arguments
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            end_length = strtoul(argv[++i], NULL, 10);
            has_end_length = 1;
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            append_file = argv[++i];
        } else if (strcmp(argv[i], "-v2") == 0) {
            is_new_format = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate operation
    int is_encode = strcmp(operation, "encode") == 0;
    int is_decode = strcmp(operation, "decode") == 0;
    
    if (!is_encode && !is_decode) {
        fprintf(stderr, "Error: Invalid operation. Must be decode, encode\n");
        return 1;
    }
    
    // Read input file
    uint8_t *data;
    size_t data_size;
    if (read_file(input_file, &data, &data_size) != 0) {
        return 1;
    }
    
    // For decode operations, create output directory
    if (is_decode) {
        create_directory(output_path);
    }
    
    // Handle end extraction for decode operations
    if (is_decode && has_end_length && end_length < data_size) {
        // Extract end data
        size_t end_size = data_size - end_length;
        uint8_t *end_data = data + end_length;
        
        // Write end data file
        char *end_output = join_path(output_path, "end.gz");
        if (end_output) {
            if (write_file(end_output, end_data, end_size) == 0) {
                printf("Extracted end.gz (" SIZE_T_FMT " bytes)\n", end_size);
            }
            free(end_output);
        }
        
        // Adjust data size to exclude end data
        data_size = end_length;
    }
    
    // Prepare key
    uint8_t key[16];
    if (is_new_format && is_encode) {
        generate_key(key, data, data_size);
    } else {
        memcpy(key, default_key, 16);
    }
    
    // Perform operation
    int result;
    if (is_encode) {
        result = encode_rootfs(data, &data_size, key, is_new_format);
    } else {
        result = decode_rootfs(data, &data_size, key, is_new_format);
        
        // Write extracted key for decode operations
        char *key_output = join_path(output_path, "key.bin");
        if (key_output) {
            write_file(key_output, key, 16);
            free(key_output);
        }
    }
    
    if (result != 0) {
        free(data);
        return 1;
    }
    
    // Handle append file for encode operations
    if (is_encode && append_file) {
        uint8_t *append_data;
        size_t append_size;
        if (read_file(append_file, &append_data, &append_size) == 0) {
            // Reallocate data to include append file
            data = realloc(data, data_size + append_size);
            if (data) {
                memcpy(data + data_size, append_data, append_size);
                data_size += append_size;
                printf("Added %s (" SIZE_T_FMT " bytes)\n", append_file, append_size);
            }
            free(append_data);
        }
    }
    
    // Write output file
    char *final_output_path;
    if (is_decode) {
        final_output_path = join_path(output_path, "rootfs.ext2");
    } else {
        final_output_path = strdup(output_path);
    }
    
    if (final_output_path) {
        if (write_file(final_output_path, data, data_size) == 0) {
            printf("%s completed successfully: %s\n", operation, final_output_path);
        }
        free(final_output_path);
    }
    
    free(data);
    return 0;
}