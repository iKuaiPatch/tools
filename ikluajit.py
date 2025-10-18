from Crypto.Cipher import AES
import zlib
import struct
import sys

data_key = bytes([
    0xFC, 0x40, 0xF8, 0x19,
    0x30, 0x9F, 0x4E, 0x73,
    0x14, 0xE4, 0x0A, 0x19,
    0x9A, 0x75, 0x1B, 0xE3
])
iv = bytes(range(16))

def decrypt_lua(file: str, output_file: str = None):
    with open(file, 'rb') as f:
        data = f.read()

    data_lenght = data[:4]
    data_lenght = struct.unpack('>I', data_lenght)[0]
    cipher_data = data[4:]

    cipher = AES.new(data_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(cipher_data)
    decrypted = decrypted[:data_lenght]

    lenght = decrypted[:4]
    lenght = struct.unpack('>I', lenght)[0]
    decrypted = decrypted[4:]

    decompressed = zlib.decompress(decrypted)

    if len(decompressed) != lenght:
        print(f"Decompressed size mismatch, expected {lenght}, got {len(decompressed)}")
        exit(1)

    if not output_file:
        output_file = file + '.lua'

    with open(output_file, 'wb') as f:
        f.write(decompressed)

    print("Decryption + decompression successful")

def main():
    if len(sys.argv) == 1:
        print("Usage: python ikluajit.py <files>")
        exit(1)

    for file in sys.argv[1:]:
        print(f"Processing {file}...")
        decrypt_lua(file)

if __name__ == "__main__":
    main()
