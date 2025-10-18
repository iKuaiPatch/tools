#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

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

int save_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening output file");
        return -1;
    }
    
    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);
    
    if (bytes_written != size) {
        perror("Error writing to output file");
        return -1;
    }
    
    return 0;
}

uint32_t crc(const char *data, uint32_t len, uint32_t skip)
{
    uint32_t sum = 0;
    uint32_t i;

    // 处理长度大于等于2的情况
    for (i = 0; i + 1 < len; i += 2) {
        // 如果当前索引*2不等于skip，就累加这个16位数据
        if (i != skip) {
            sum += *(const uint16_t *)(data + i);
        }
    }

    // 如果长度为奇数，处理最后一个字节
    if (len % 2 == 1) {
        sum += (uint8_t)data[len - 1];
    }

    // 将高16位累加到低16位
    sum = (sum & 0xFFFF) + (sum >> 16);
    // 再一次处理可能溢出的高16位
    sum = (sum & 0xFFFF) + (sum >> 16);

    // 取反返回
    return ~sum;
}

uint32_t read_be32(const uint8_t *data) {
    return (uint32_t)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
}

uint16_t read_be16(const uint8_t *data) {
    return (uint16_t)(data[0] << 8 | data[1]);
}

uint32_t read_le32(const uint8_t *data) {
    return (uint32_t)(data[3] << 24 | data[2] << 16 | data[1] << 8 | data[0]);
}

uint16_t read_le16(const uint8_t *data) {
    return (uint16_t)(data[1] << 8 | data[0]);
}

uint8_t *hex2bin(const char *hex, size_t *out_size) {
    size_t len = 0;
    while (hex[len] != '\0') {
        len++;
    }
    if (len % 2 != 0) {
        return NULL; // Hex string length must be even
    }

    size_t bin_size = len / 2;
    uint8_t *bin = (uint8_t *)malloc(bin_size);
    if (!bin) {
        return NULL; // Memory allocation failed
    }

    for (size_t i = 0; i < bin_size; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }

    *out_size = bin_size;
    return bin;
}

void unpack() {
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x17, 0xea, 0xe4,
        0xf5, 0x12, 0x1e, 0x39, 0x07, 0xb2,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x95, 0x51, 0x40, 0x10
    };

    /*
        0       Message type                 : 0x0
        1       Message version              : 0x0
        2  - 4  Length (big-endian)          : 0x0017 (23)
        4  - 6  CRC16 (little-endian)        : 0xE4EA
        6  - 8  Seed (little-endian)         : 0xF512
        8  - 12 Random (little-endian)       : 0xB207391E
        12 - 16 Reserved                     : 0x00000000
        16      REQ flag                     : 0x0
        17 - 19 REQ lenght                   : 0x0007
        19 - 23 Version (big-endian)         : 0x95514010 (2505130000)
    */

    uint16_t header = read_be16(data);
    uint16_t lenght = read_be16(data + 2);
    uint16_t crc_val = read_le16(data + 4);
    uint16_t seed = read_le16(data + 6);
    seed = (seed << 8) | (seed >> 8);
    uint32_t random = read_le32(data + 8);
    uint8_t req_flag = data[16];
    uint16_t req_lenght = read_be16(data + 17);
    uint32_t version = read_be32(data + 19);

    printf("Header      : %04X\n", header);
    printf("Data Length : %d\n", lenght);
    printf("Length      : %08X\n", lenght);
    printf("Seed        : %04X\n", seed);
    printf("Random      : %08X\n", random);
    printf("Embedded CRC: %04X\n", crc_val);
    printf("Flag        : %02X\n", req_flag);
    printf("REQ Length  : %u\n", req_lenght);
    printf("Version     : %u (0x%08X)\n", version, version);
}

void unpack2() {
    char *hex = "020002899674b4b7c3b00e7800000000000007955144c0010272f4442f2985563baeb8f518ebb81ca0933958743bfcccbf141dfcd4e29cdb458b298576e237d73fed41a67317ba0447ddc96abbb5854367b4a8fb3e0d7c86549f093f2121bd2de7f859c4790d7abb39d0e58212c704b923d5c92c81d59e84ac42ef4e041969a647568cdf82c148aa18836e0982b3c15aa8ba3516fcb1e18f8d62c97636ab978b5c26adff65b982659024d373307b44931f00a5cb45db188f0c02996eaaf7e9788c6c6978e6164283cce5cd52235efaaf446a9cea3445f0db1480b1cd5356d7d7de797959687da83060752d484ac08ff393b23dfe7c10dddd836de61603445dd322bdff4f2841fdb0b0ee5931b82f496fe247758ff003e4d5d4e955336acfda4a599257c05722ba92624d645286e9c5b604a944b13ce1f1a47854a8595b243d5334a4655fd448d650dec549174ecbbb30349812b4c3f2044246eb26059b0a291d2cc588953045d5885c8d503d3f53623718883943baea1a0322912165a2b50b26123d86fda8f8e3374acfe7267fafb3e08a35427ba3f9a15c6f693ee14147435d8e60ec67950dbc5d7c02f1722dd86b6872d959dbf318674db7f9deca05c98b7aee182ea381cd950f14410ec4ed1f682163b031e37afd776dee267d9b5a7d940ed9055e031f74b46f3548a27067b3fb6009f2508728407f6fb721f4694f0f0a0651106d0013dc6c91d2e7a18566613958bde532e803581923632e16957b06b788f5d6a727cc55f3133cf5e6fa337fc340e9f451e4f7c8fa1bb6cb85124ac6fcba63d5e556ef5c79f7c42200989bf0df58ea4a8ba72a39ef787fe9ee87c2144683add825370470e1af3d41a8e56e68c4957aed80aec3e756df1ed2db5a79a83b2eabb5fc4f0e236cf7cb";
    size_t bin_size;
    uint8_t *data = hex2bin(hex, &bin_size);
    if (!data) {
        printf("Failed to convert hex to bin\n");
        return;
    }

/*
    Header:
        0       Message type                 : 0x02
        1       Message version              : 0x00
        2  - 4  Length (big-endian)          : 0x0289 (649)
        4  - 6  CRC16 (little-endian)        : 0x7496
        6  - 8  Seed (little-endian)         : 0xB4B7
        8  - 12 Random (little-endian)       : 0xC3B00E78
        12 - 16 Reserved                     : 0x00000000
    Data 1:
        16      ACK flag                     : 0x0
        17 - 19 ACK lenght                   : 0x0007
        19 - 23 Version (big-endian)         : 0x955144C0 (2505131200)
    Data 2:
        23      ACK2 flag                    : 0x1
        24 - 26 ACK2 lenght                  : 0x272 (626)
        26 - ... Data                        : ...
*/

    uint8_t msg_type = data[0];
    uint8_t msg_version = data[1];
    uint16_t lenght = read_be16(data + 2);
    uint16_t crc_val = read_be16(data + 4);
    uint16_t seed = read_be16(data + 6);
    uint32_t random = read_le32(data + 8);

    printf("Msg Type    : %02X\n", msg_type);
    printf("Msg Version : %02X\n", msg_version);
    printf("Data Length : %d\n", lenght);
    printf("Length      : %08X \n", lenght);
    printf("Seed        : %04X\n", seed);
    printf("Random      : %08X\n", random);
    printf("Embedded CRC: %04X\n", crc_val);
    hexdump(data + 12, 4);

    uint16_t computed_crc = (uint16_t)crc((const char *)data, 16, 4);
    printf("Computed CRC: %04X\n", computed_crc);

    uint32_t tmp = (((uint32_t)seed + 0xDEADBEEF) * 0xDEADBEEF) / 0x83;
    random = tmp * 0x5C6B7;
    random = (random >> 24) | ((random & 0xFF0000) >> 8) | ((random & 0xFF00) << 8) | (tmp * 0xB7000000);
    printf("Computed Rnd: %08X\n", random);

    uint8_t ack_flag = data[16];
    uint16_t ack_lenght = read_be16(data + 17);
    uint32_t version = read_be32(data + 19);
    
    printf("Flag        : %02X\n", ack_flag);
    printf("ACK Length  : %u\n", ack_lenght);
    printf("Version     : %u (0x%08X)\n", version, version);

    ack_flag = data[23];
    ack_lenght = read_be16(data + 24);
    printf("ACK2 Flag   : %02X\n", ack_flag);
    printf("ACK2 Length : %u\n", ack_lenght);
    hexdump(data + 26, ack_lenght - 3);

    // hexdump(data + 23, (int)(lenght - 23));
    save_file("output.bin", data + 26, ack_lenght - 3);

    free(data);
}

uint16_t get_seed() {
    return 0x12F5;
}

int main() {
    // unpack();
    unpack2();

    uint8_t data[23] = {0};

    data[0] = 0x00;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x17; // Length = 16 + 7 = 23


    uint16_t seed = get_seed();
    seed = (seed << 8) | (seed >> 8);
    data[6] = (uint8_t)((seed >> 8) & 0xFF);
    data[7] = (uint8_t)(seed & 0xFF);

    uint32_t tmp = (((uint32_t)seed + 0xDEADBEEF) * 0xDEADBEEF) / 0x83;
    uint32_t random = tmp * 0x5C6B7;
    random = (random >> 24) | ((random & 0xFF0000) >> 8) | ((random & 0xFF00) << 8) | (tmp * 0xB7000000);
    data[8]  = (uint8_t)(random & 0xFF);
    data[9]  = (uint8_t)((random >> 8) & 0xFF);
    data[10] = (uint8_t)((random >> 16) & 0xFF);
    data[11] = (uint8_t)((random >> 24) & 0xFF);

    hexdump(data, 16);
    uint16_t checksum16 = (uint16_t)crc((const char *)data, 16, 4);
    printf("CRC16: %04X\n", checksum16);
    checksum16 = (checksum16 << 8) | (checksum16 >> 8);
    data[4] = (uint8_t)(checksum16 & 0xFF);
    data[5] = (uint8_t)((checksum16 >> 8) & 0xFF);

    
    data[12] = 0x00;
    data[13] = 0x00;
    data[14] = 0x00;
    data[15] = 0x00;

    data[16] = 0x00;
    data[17] = 0x00;
    data[18] = 0x07;

    uint32_t version = 2505130000;
    data[19] = (uint8_t)((version >> 24) & 0xFF);
    data[20] = (uint8_t)((version >> 16) & 0xFF);
    data[21] = (uint8_t)((version >> 8) & 0xFF);
    data[22] = (uint8_t)(version & 0xFF);


    // hexdump(data, 23);

    return 0;
}


