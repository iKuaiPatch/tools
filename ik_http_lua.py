import struct
import hashlib
import zlib
import os
import sys

key = bytes([0x66, 0x16, 0x7E, 0x74, 0x74, 0x6C, 0x3B, 0xB9,
             0xC4, 0x86, 0x8C, 0xAC, 0x9D, 0x30, 0x18, 0x96])

def checksum(data: bytes) -> int:
    if len(data) <= 0:
        return -1
    result = 0

    for i in range(0, len(data), 2):
        result += (data[i] << 8) + data[i + 1]
    
    return (~result) & 0xFFFF

def decrypt(input_bytes: bytes, key: bytes, checksum_val: int) -> bytes:
    input_bytes = bytearray(input_bytes)
    key_len = len(key)
    ext_key = bytearray((checksum_val * k) & 0xFF for k in key)
    for i in range(len(input_bytes)):
        cur_key = ext_key[i % key_len]
        val = (input_bytes[i] - cur_key) & 0xFF
        shift = (((cur_key * 0x925) >> 11) + 1) & 7
        input_bytes[i] = ((val << shift) | (val >> (8 - shift))) & 0xFF
    return bytes(input_bytes)

def read_be16(data: bytes) -> int:
    return struct.unpack('>H', data)[0]

def read_be32(data: bytes) -> int:
    return struct.unpack('>I', data)[0]

def process_file(path: str, output_dir: str):
    with open(path, 'rb') as f:
        while True:
            start = f.tell()

            hash_val = f.read(2)
            if not hash_val:
                print("Finished processing file.")
                break

            hash_val = read_be16(hash_val)

            # 校验 head
            offset = f.tell()
            if hash_val != checksum(f.read(62)):
                print("Checksum failure")
                return
            f.seek(offset)
            
            # 读取文件名
            file_name_lenght = f.read(2)
            file_name_lenght = read_be16(file_name_lenght)

            # 读取数据长度
            file_data_length = f.read(4)
            file_data_length = read_be32(file_data_length)

            # 读取 MD5
            expected_md5 = f.read(16)

            # 跳过校验头
            f.seek(start + 64)

            # 解密文件名
            enc_name = f.read(file_name_lenght)
            file_name = decrypt(enc_name, key, hash_val).decode('utf-8', errors='ignore')

            # 解密数据
            enc_data = f.read(file_data_length)
            data = decrypt(enc_data, key, hash_val)

            md5 = hashlib.md5(data).digest()
            if md5 != expected_md5:
                print(f"MD5 mismatch for {file_name}")
                return
            
            # 获取解密后数据长度
            data_size = data[:4]
            data_size = read_be32(data_size)

            # zlib 解压
            data = data[4:]
            decompressed = zlib.decompress(data)

            if len(decompressed) != data_size:
                print(f"Decompressed size mismatch for {file_name}, expected {data_size}, got {len(decompressed)}")
                return

            with open(f'{output_dir}/{file_name}', 'wb') as ff:
                ff.write(decompressed)

def main():
    if len(sys.argv) < 3:
        print("Usage: python ik_http_lua.py <input_file> <output_directory>")
        exit(1)
    
    input_file = sys.argv[1]
    output_directory = sys.argv[2]

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    process_file(input_file, output_directory)

if __name__ == "__main__":
    main()

