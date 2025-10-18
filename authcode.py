import struct
import time
import hashlib
from Crypto.Cipher import AES
import sys

def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)
    return encrypted

def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def build_auth_code_packet(auth_code: bytes, timestamp: int) -> bytes:
    tlv_data = bytearray()

    # TLV type=1: auth_code
    tlv_data += struct.pack("<B", 1)                   # type
    tlv_data += struct.pack("<H", len(auth_code))      # length (little-endian)
    tlv_data += auth_code                              # value

    # TLV type=2: time
    tlv_data += struct.pack("<B", 2)                   # type
    tlv_data += struct.pack("<H", 4)                   # length=4
    tlv_data += struct.pack("<I", timestamp)           # value (uint32)

    # 头部
    raw_data = bytearray()
    raw_data.append(1)                                 # raw_data[0] 保留
    raw_data.append(len(tlv_data) + 3)                 # raw_data[1] 长度 = TLV总长+3
    raw_data.append(0)                                 # raw_data[2] 保留
    raw_data += tlv_data

    return bytes(raw_data)

def generate_auth_code_body(auth_data: bytes) -> bytes:
    # 计算 md5
    auth_md5 = md5(auth_data)
    
    # padding 到 16 字节的倍数
    if len(auth_data) % 16 != 0:
        padding_length = 16 - (len(auth_data) % 16)
        auth_data += b'\x00' * padding_length

    return auth_md5 + auth_data

def generate_auth_key(gwid: bytes, mac: bytes, timestamp: int) -> bytes:
    # md5(gwcode)
    gwcode = gwid + mac
    gwcode = gwcode[:64]
    gw_md5 = md5(gwcode)
    
    # md5(time)
    time_bytes = timestamp.to_bytes(4, 'little')  # 对应C里的 &code->time
    time_md5 = md5(time_bytes)
    
    # XOR 前16字节
    xor_bytes = bytearray(gw_md5)
    for i in range(16):
        xor_bytes[i] ^= time_md5[i]
    
    # 再 MD5
    key = md5(bytes(xor_bytes[:16]))
    return key

def generate_iv(gwid: bytes, mac: bytes, timestamp: int) -> bytes:
    # md5(gwcode)
    gwcode = str(timestamp).encode() + gwid + mac
    gwcode = gwcode[:64]
    return md5(gwcode)

def generate_machine_code(mac: str) -> str:
    """
    生成机器码

    Args:
        mac (str): MAC 地址
    """
    salt = b"c*e9pg17Q7TzbR4YK3gO8WFo*086*t0@"
    mac_bytes = mac.replace(":", "").encode()
    combined = mac_bytes + salt
    return hashlib.md5(combined).hexdigest()

def generate_gv_auth_code(machine_code: str, gwid: str, mac: str) -> str:
    """
    生成 Genuine verification 认证码

    Args:
        machine_code (str): 机器码
        gwid         (str): 路由器ID
        mac          (str): MAC 地址
    """
    machine_code_cal = generate_machine_code(mac)
    if machine_code_cal != machine_code:
        print("Machine code does not match the calculated machine code from MAC address.")
        print(f"Calculated machine code: {machine_code_cal}")
        print(f"Provided machine code:   {machine_code}")
        return ''
    
    machine_code = machine_code.encode()
    gwid = gwid.encode()
    
    result = machine_code + b'RD.Ikuai8dotCom' + gwid
    result = md5(result)
    return result.hex()

def generate_auth_code(name: str, gwid: str, mac: str):
    """
    生成认证码

    Args:
        name (str): 设备名称
        gwid (str): 路由器ID
        mac (str): MAC 地址
    """
    timestamp = int(time.time())
    
    name = name.encode()
    gwid = gwid.encode()
    mac = mac.encode()

    key = generate_auth_key(gwid, mac, timestamp)
    iv = generate_iv(gwid, mac, timestamp)

    auth_code = generate_auth_code_body(name)

    data = aes_encrypt(auth_code, key, iv)

    packet = build_auth_code_packet(data, timestamp)

    return packet.hex()

def usage():
    print("Usage: python authcode.py <authcode|gvcode> <name|machine_code> <gwid> <mac>")
    print("  authcode: 生成认证码")
    print("  gvcode:   生成 Genuine verification 认证码")
    print("Example:")
    print("  python authcode.py authcode IK-R1200 65284c225d3948c0a0760bde94775b8d 7F:44:E1:8D:C0:F7")
    print("  python authcode.py gvcode 67d826c3167a50a42bd199371ab119d2 65284c225d3948c0a0760bde94775b8d 7F:44:E1:8D:C0:F7")

def main():
    if len(sys.argv) != 5:
        usage()
        return

    mode = sys.argv[1]
    if mode == "authcode":
        name = sys.argv[2]
        gwid = sys.argv[3]
        mac = sys.argv[4]
        print(f"Generating auth code for device name: {name}, gwid: {gwid}, mac: {mac}")
        auth_code = generate_auth_code(name, gwid, mac)
        print('Auth code:', auth_code)
    elif mode == "gvcode":
        machine_code = sys.argv[2]
        gwid = sys.argv[3]
        mac = sys.argv[4]
        print(f"Generating Genuine verification code for machine_code: {machine_code}, gwid: {gwid}, mac: {mac}")
        gv_code = generate_gv_auth_code(machine_code, gwid, mac)
        print('Genuine verification code:', gv_code)
    else:
        usage()

if __name__ == "__main__":
    main()
