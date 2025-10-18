import struct
import io
from decrypt import init_key, decrypt, hexdump
import time
import uuid
import base64
import socket

# Header:
#     0       Message type                 : send: 0x00, recv: 0x02
#     1       Message version              : 0x00
#     2  - 4  Length (big-endian)          : 0x0289 (649)
#     4  - 6  CRC16 (little-endian)        : 0x7496
#     6  - 8  Seed (little-endian)         : 0xB4B7
#     8  - 12 Random (little-endian)       : 0xC3B00E78
#     12 - 16 Reserved                     : 0x00000000
# Data 1:
#     16      ACK flag                     : 0x00
#     17 - 19 ACK lenght (big-endian)      : 0x0007
#     19 - 23 Version (big-endian)         : 0x955144C0 (2505131200)
# Data 2:
#     23      ACK2 flag                    : 0x01
#     24 - 26 ACK2 lenght (big-endian)     : 0x272 (626)
#     26 - ... Data                        : ...

server = {
	"urls": [
        "https://123.56.230.35:20135/get_hosts/",
		"https://py-1251915786.cos.ap-beijing.myqcloud.com/",
		"https://ikyun.oss-cn-beijing.aliyuncs.com/",
		"https://123.56.221.14:20135/get_hosts/",
		"https://39.97.211.81:20135/get_hosts/",
		"https://58.87.115.174:20135/get_hosts/",
		"https://81.68.84.99:20135/get_hosts/",
		"https://182.254.205.25:20135/get_hosts/",
		"https://118.25.226.116:20135/get_hosts/",
		"https://58.87.67.57:20135/get_hosts/"
    ],
	"servers":[
        "123.56.230.35:20135",
		"123.56.221.14:20135",
		"39.97.211.81:20135",
		"58.87.115.174:20135",
		"81.68.84.99:20135",
		"182.254.205.25:20135",
		"118.25.226.116:20135",
		"58.87.67.57:20135"
    ]
}

version_url = 'rAVKB3uJo0AGIfm0SOAj?'
hosts_url = 'Xca758pKhtcwlNwhypx0'

def get_version_url(url: str) -> str:
    random_gwid = base64.b64encode(uuid.uuid4().bytes).decode()
    return url + version_url + random_gwid

def get_hosts_url(url: str) -> str:
    return url + hosts_url

def checksum(data: bytes, skip: int = 4) -> int:
    sum = 0
    for i in range(0, len(data), 2):
        if i == skip:
            continue
        sum += struct.unpack('<H', data[i:i+2])[0]
    
    if len(data) % 2 == 1:
        sum = (sum + data[-1]) & 0xFFFF
    
    sum = (sum & 0xFFFF) + (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16)

    return (~sum) & 0xFFFF

def crc32(seed) -> int:
    seed = seed & 0xFFFFFFFF
    tmp = (seed + 0xDEADBEEF) & 0xFFFFFFFF
    tmp = (tmp * 0xDEADBEEF) & 0xFFFFFFFF
    tmp = (tmp // 0x83) & 0xFFFFFFFF
    crc32 = (tmp * 0x5C6B7) & 0xFFFFFFFF
    crc32 = (
        (crc32 >> 24) |
        ((crc32 & 0xFF0000) >> 8) |
        ((crc32 & 0xFF00) << 8) |
        ((tmp * 0xB7000000) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF
    return crc32

def read_be16(data: bytes) -> int:
    return struct.unpack('>H', data)[0]

def read_be32(data: bytes) -> int:
    return struct.unpack('>I', data)[0]

def read_le32(data: bytes) -> int:
    return struct.unpack('<I', data)[0]

g_key = init_key()

def handle_message(data: bytes):
    data = io.BytesIO(data)
    
    while True:
        flag = data.read(1)
        if len(flag) == 0:
            break
        flag = flag[0]
        
        length = read_be16(data.read(2)) - 3
        print(f"Flag: {flag:02X}, Length: {length}")
        chunk = data.read(length)
        print(f"Data ({len(chunk)} bytes):")
        
        if flag == 0x00:
            version = read_be32(chunk)
            print(f"Version: {version}")
        elif flag == 0x01:
            print(decrypt(g_key, chunk).decode(errors='ignore'))
        else:
            print(f"Unknown flag: {flag.hex()}")
            hexdump(chunk)

process = {
    0x00: handle_message, # Send
    0x01: None, # Chekc crc
    0x02: handle_message, # Recv
}

def process_data(data: bytes):
    data_lenght = len(data)
    if data_lenght < 16:
        raise ValueError("Data too short")
    
    header = data[:16]
    data = io.BytesIO(data)

    msg_type = data.read(1)
    msg_version = data.read(1)
    msg_length = read_be16(data.read(2))

    if msg_length != data_lenght:
        print(f"Length check failed: {msg_length} != {len(data)}")
        raise ValueError("Length check failed")

    msg_checksum = read_be16(data.read(2))
    msg_seed = read_be16(data.read(2))
    msg_random = read_le32(data.read(4))
    reversed = data.read(4)
    
    print(f"Message type      : {msg_type.hex()}")
    print(f"Message version   : {msg_version.hex()}")
    print(f"Message length    : {msg_length}")
    print(f"Message checksum  : {msg_checksum:04X}")
    print(f"Message seed      : {msg_seed:04X}")
    print(f"Message crc32     : {msg_random:08X}")
    print(f"Message reversed  : {reversed.hex()}")

    checksum_val = checksum(header, 4)
    if checksum_val != msg_checksum:
        print(f"Checksum failed: {checksum_val:04X} != {msg_checksum:04X}")
        raise ValueError("CRC check failed")
    
    crc32_val = crc32(msg_seed)
    if crc32_val != msg_random:
        print(f"Crc32 check failed: {crc32_val:08X} != {msg_random:08X}")
        raise ValueError("Random check failed")

    if msg_type[0] not in process:
        raise ValueError(f"Unknown message type: {msg_type.hex()}")
    
    if process[msg_type[0]] is None:
        return
    
    process[msg_type[0]](data.read(msg_length - 16))

def packet_send(version: int):
    seed = int(time.time()) & 0xFFFF
    crc32_val = crc32(seed)

    body = bytearray()
    body.append(0x00) # REQ flag
    body += struct.pack('>H', 7) # REQ length
    body += struct.pack('>I', version) # Version

    packet = bytearray(16)
    packet[0] = 0x00 # Message type
    packet[1] = 0x00 # Message version

    struct.pack_into('>H', packet, 2, 16 + len(body)) # Length
    struct.pack_into('>H', packet, 6, seed) # Seed
    struct.pack_into('<I', packet, 8, crc32_val) # Crc32

    struct.pack_into('>H', packet, 4, checksum(packet, 4)) # Checksum

    packet += body

    return bytes(packet)

def udp_send(ip: str, port: int, local_version: int = 0):
    addr = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    packet = packet_send(local_version)
    print(f"Sending {len(packet)} bytes to {ip}:{port}")
    hexdump(packet)
    sock.sendto(packet, addr)

    try:
        data, _ = sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {ip}:{port}")
        process_data(data)
    except socket.timeout:
        print("No response received")
        return None
    finally:
        sock.close()

server_ip, server_port = server['servers'][0].split(':')
udp_send(server_ip, int(server_port), local_version=0x0)
