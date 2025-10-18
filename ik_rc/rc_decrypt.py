import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import io
from dataclasses import dataclass
from enum import Enum

def crc16(data: bytes) -> int:
    """
    CRC16
    Sum all bytes except last two, mod 2^16
    """
    crc = 0
    for b in data:
        crc = (crc + b) & 0xFFFF
    return crc & 0xFFFF

def evp_bytes_to_key(password: bytes, key_len: int, iv_len: int, md='sha1', count=5) -> tuple[bytes, bytes]:
    required = key_len + iv_len
    derived = b''
    prev = b''
    while len(derived) < required:
        d = prev + password
        for _ in range(count):
            d = hashlib.new(md, d).digest()
        derived += d
        prev = d
    return derived[:key_len], derived[key_len:key_len+iv_len]

# 1: heartbeat_req
# 2: heartbeat_resp
# 3：auth_req
# 4：auth_resp
# 5：rest_ctrl_req
# 6：rest_ctrl_resp
# 7：disconn_req
# 8：session_end
class DataType(Enum):
    HEARTBEAT_REQ = 1
    HEARTBEAT_RESP = 2
    AUTH_REQ = 3
    AUTH_RESP = 4
    REST_CTRL_REQ = 5
    REST_CTRL_RESP = 6
    DISCONN_REQ = 7
    SESSION_END = 8

@dataclass
class RCData:
    header: int
    timestamp: int
    session_id: int
    data_type: DataType
    data: bytes

def decrypt_rc_data(data: bytes, key: bytes) -> list[RCData]:
    data = io.BytesIO(data)
    key, iv = evp_bytes_to_key(key, 32, 16, 'sha1', 5)

    # 大端序
    # [0-1]: 包头（2字节）
    # [2-5]: 数据包总长度（4字节）
    # [6-9]: 时间戳（4字节）
    # [10-13]: 会话ID（4字节）
    # [14]: 数据类型（1字节）
    # [15]: AES 加密（2字节）
    # [16...]: 数据载荷
    # [最后2字节]: CRC校验和

    result = []

    while True:
        start = data.tell()

        headre = data.read(2)
        if not headre:
            break
        headre = struct.unpack('>H', headre)[0]

        lenght = struct.unpack('>I', data.read(4))[0] - 16 - 2

        timestamp = struct.unpack('>I', data.read(4))[0]
        sid = struct.unpack('>I', data.read(4))[0]

        data_type = struct.unpack('B', data.read(1))[0]
        is_aes = struct.unpack('B', data.read(1))[0] == 0xa0

        raw_data = data.read(lenght)

        crc = struct.unpack('>H', data.read(2))[0]

        offset = data.tell()

        data.seek(start)

        crc_cal = crc16(data.read(offset - start - 2))

        data.seek(offset)

        if crc != crc_cal:
            print("CRC mismatch", hex(crc), hex(crc_cal))
            continue

        if lenght != len(raw_data):
            print("Length mismatch", lenght, len(raw_data))
            continue

        if is_aes:
            ciphet = AES.new(key, AES.MODE_CBC, iv=iv)
            raw_data = ciphet.decrypt(raw_data)
            raw_data = unpad(raw_data, AES.block_size)
        
        result.append(RCData(
            header=headre,
            timestamp=timestamp,
            session_id=sid,
            data_type=DataType(data_type),
            data=raw_data
        ))

    return result
