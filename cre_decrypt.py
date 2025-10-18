from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import gzip
import io
from dataclasses import dataclass

hash_table = [
    0x0,           0x77073096,    0xEE0E612C,    0x990951BA,
    0x76DC419,     0x706AF48F,    0xE963A535,    0x9E6495A3,
    0xEDB8832,     0x79DCB8A4,    0xE0D5E91E,    0x97D2D988,
    0x9B64C2B,     0x7EB17CBD,    0xE7B82D07,    0x90BF1D91,
    0x1DB71064,    0x6AB020F2,    0xF3B97148,    0x84BE41DE,
    0x1ADAD47D,    0x6DDDE4EB,    0xF4D4B551,    0x83D385C7,
    0x136C9856,    0x646BA8C0,    0xFD62F97A,    0x8A65C9EC,
    0x14015C4F,    0x63066CD9,    0xFA0F3D63,    0x8D080DF5,
    0x3B6E20C8,    0x4C69105E,    0xD56041E4,    0xA2677172,
    0x3C03E4D1,    0x4B04D447,    0xD20D85FD,    0xA50AB56B,
    0x35B5A8FA,    0x42B2986C,    0xDBBBC9D6,    0xACBCF940,
    0x32D86CE3,    0x45DF5C75,    0xDCD60DCF,    0xABD13D59,
    0x26D930AC,    0x51DE003A,    0xC8D75180,    0xBFD06116,
    0x21B4F4B5,    0x56B3C423,    0xCFBA9599,    0xB8BDA50F,
    0x2802B89E,    0x5F058808,    0xC60CD9B2,    0xB10BE924,
    0x2F6F7C87,    0x58684C11,    0xC1611DAB,    0xB6662D3D,
    0x76DC4190,    0x1DB7106,     0x98D220BC,    0xEFD5102A,
    0x71B18589,    0x6B6B51F,     0x9FBFE4A5,    0xE8B8D433,
    0x7807C9A2,    0xF00F934,     0x9609A88E,    0xE10E9818,
    0x7F6A0DBB,    0x86D3D2D,     0x91646C97,    0xE6635C01,
    0x6B6B51F4,    0x1C6C6162,    0x856530D8,    0xF262004E,
    0x6C0695ED,    0x1B01A57B,    0x8208F4C1,    0xF50FC457,
    0x65B0D9C6,    0x12B7E950,    0x8BBEB8EA,    0xFCB9887C,
    0x62DD1DDF,    0x15DA2D49,    0x8CD37CF3,    0xFBD44C65,
    0x4DB26158,    0x3AB551CE,    0xA3BC0074,    0xD4BB30E2,
    0x4ADFA541,    0x3DD895D7,    0xA4D1C46D,    0xD3D6F4FB,
    0x4369E96A,    0x346ED9FC,    0xAD678846,    0xDA60B8D0,
    0x44042D73,    0x33031DE5,    0xAA0A4C5F,    0xDD0D7CC9,
    0x5005713C,    0x270241AA,    0xBE0B1010,    0xC90C2086,
    0x5768B525,    0x206F85B3,    0xB966D409,    0xCE61E49F,
    0x5EDEF90E,    0x29D9C998,    0xB0D09822,    0xC7D7A8B4,
    0x59B33D17,    0x2EB40D81,    0xB7BD5C3B,    0xC0BA6CAD,
    0xEDB88320,    0x9ABFB3B6,    0x3B6E20C,     0x74B1D29A,
    0xEAD54739,    0x9DD277AF,    0x4DB2615,     0x73DC1683,
    0xE3630B12,    0x94643B84,    0xD6D6A3E,     0x7A6A5AA8,
    0xE40ECF0B,    0x9309FF9D,    0xA00AE27,     0x7D079EB1,
    0xF00F9344,    0x8708A3D2,    0x1E01F268,    0x6906C2FE,
    0xF762575D,    0x806567CB,    0x196C3671,    0x6E6B06E7,
    0xFED41B76,    0x89D32BE0,    0x10DA7A5A,    0x67DD4ACC,
    0xF9B9DF6F,    0x8EBEEFF9,    0x17B7BE43,    0x60B08ED5,
    0xD6D6A3E8,    0xA1D1937E,    0x38D8C2C4,    0x4FDFF252,
    0xD1BB67F1,    0xA6BC5767,    0x3FB506DD,    0x48B2364B,
    0xD80D2BDA,    0xAF0A1B4C,    0x36034AF6,    0x41047A60,
    0xDF60EFC3,    0xA867DF55,    0x316E8EEF,    0x4669BE79,
    0xCB61B38C,    0xBC66831A,    0x256FD2A0,    0x5268E236,
    0xCC0C7795,    0xBB0B4703,    0x220216B9,    0x5505262F,
    0xC5BA3BBE,    0xB2BD0B28,    0x2BB45A92,    0x5CB36A04,
    0xC2D7FFA7,    0xB5D0CF31,    0x2CD99E8B,    0x5BDEAE1D,
    0x9B64C2B0,    0xEC63F226,    0x756AA39C,    0x26D930A,
    0x9C0906A9,    0xEB0E363F,    0x72076785,    0x5005713,
    0x95BF4A82,    0xE2B87A14,    0x7BB12BAE,    0xCB61B38,
    0x92D28E9B,    0xE5D5BE0D,    0x7CDCEFB7,    0xBDBDF21,
    0x86D3D2D4,    0xF1D4E242,    0x68DDB3F8,    0x1FDA836E,
    0x81BE16CD,    0xF6B9265B,    0x6FB077E1,    0x18B74777,
    0x88085AE6,    0xFF0F6A70,    0x66063BCA,    0x11010B5C,
    0x8F659EFF,    0xF862AE69,    0x616BFFD3,    0x166CCF45,
    0xA00AE278,    0xD70DD2EE,    0x4E048354,    0x3903B3C2,
    0xA7672661,    0xD06016F7,    0x4969474D,    0x3E6E77DB,
    0xAED16A4A,    0xD9D65ADC,    0x40DF0B66,    0x37D83BF0,
    0xA9BCAE53,    0xDEBB9EC5,    0x47B2CF7F,    0x30B5FFE9,
    0xBDBDF21C,    0xCABAC28A,    0x53B39330,    0x24B4A3A6,
    0xBAD03605,    0xCDD70693,    0x54DE5729,    0x23D967BF,
    0xB3667A2E,    0xC4614AB8,    0x5D681B02,    0x2A6F2B94,
    0xB40BBE37,    0xC30C8EA1,    0x5A05DF1B,    0x2D02EF8D
]

key = b'kAvzrx<y$&ptMb4tzeawad1vl2wNjak9'
iv = b'xl)4Yi9Av6]P6_ys'

@dataclass
class PackageHeader:
    head: bytes
    is_aes: int
    is_recv: int
    data_len: int
    is_gzip: int
    reserved: bytes
    body_len: int
    hash: int

def get_hash(data: bytes, salt: bytes = b'') -> int:
    result = 0xFFFFFFFF
    for b in data:
        result = ((result >> 8) ^ hash_table[(b ^ result) & 0xFF]) & 0xFFFFFFFF
    for b in salt:
        result = ((result >> 8) ^ hash_table[(b ^ result) & 0xFF]) & 0xFFFFFFFF
    return (~result) & 0xFFFFFFFF

def read_be32(b: bytes) -> int:
    """Read big-endian 32-bit value."""
    return ((b[0] << 24) | (b[1] << 16) |
            (b[2] << 8)  |  b[3])

def unpacket(data: bytes) -> PackageHeader:
    head     = data[0:2]
    is_aes   = data[2]
    is_recv  = data[3]
    data_len = read_be32(data[4:8])
    is_gzip  = data[8]
    reserved = data[9:12]
    body_len = read_be32(data[12:16])
    hash = read_be32(data[16:20])

    hash_cal = get_hash(data[:16], b"}Mli")
    check = hash == hash_cal
    if check:
        print("Hash check: passed")
    else:
        print(f"Hash check: failed (expected 0x{hash:08X}, got 0x{hash_cal:08X})")


    print(f"Header: {head.hex()}")
    print(f"is_aes: {is_aes}")
    print(f"is_recv: {is_recv}")
    print(f"data_len: {data_len}")
    print(f"is_gzip: {is_gzip}")
    print(f'Reserved: {reserved}')
    print(f"body_len: {body_len}\n\n")

    return PackageHeader(
        head=head,
        is_aes=is_aes,
        is_recv=is_recv,
        data_len=data_len,
        is_gzip=is_gzip,
        reserved=reserved,
        body_len=body_len,
        hash=hash
    )


def parse_payload(data: bytes) -> tuple[dict[str, str] | None, bytes | None]:
    header_end = data.find(b'\n\n')
    if header_end == -1:
        # 没有消息体
        header_bytes = data
        body_bytes = b''
    else:
        header_bytes = data[:header_end]
        body_bytes = data[header_end+3:]
    
    if header_bytes.startswith(b'{"') or header_bytes.startswith(b'['):
        # JSON 数据，没有 Header
        return None, data

    headers = {}
    for line in header_bytes.split(b'\n'):
        if b':' in line:
            key, value = line.split(b':', 1)
            headers[key.decode().strip()] = value.decode().strip()

    # 仅当 compress=1 且 body 不为空时才解压
    if headers.get('compress') == '1' and headers.get('content-length', '') != '' and body_bytes:
        len_body = int(headers.get('content-length', ''))
        body_bytes = body_bytes[:len_body]
        try:
            body = gzip.decompress(body_bytes)
        except Exception:
            body = body_bytes
    else:
        body = body_bytes

    return headers, body

def get_body(header: PackageHeader, data: bytes) -> bytes:
    body_len = header.body_len
    
    if body_len + 4 != len(data):
        raise ValueError(f"Body length mismatch: expected {body_len + 4}, got {len(data)}")
    
    hash = read_be32(data[body_len:body_len + 4])
    hash_val = get_hash(data[:body_len])

    if hash != hash_val:
        print(f"Body hash check: failed (expected 0x{hash:08X}, got 0x{hash_val:08X})")
    else:
        print("Body hash check: passed")
    
    return data[:body_len]

def decrypt(data: bytes) -> tuple[str | None, str | None]:
    buffer = io.BytesIO(data)
    header = unpacket(buffer.read(20))
    body = buffer.read(header.body_len + 4)
    body = get_body(header, body)

    if header.is_aes:
        if body.startswith(b'Salted__'):
            body = body[len(b'Salted__'):] # 去掉前缀
        cipher = AES.new(key, AES.MODE_CBC, iv)
        body = cipher.decrypt(body)
        body = unpad(body, AES.block_size)

    if header.is_gzip == 1:
        try:
            body = gzip.decompress(body)
        except Exception:
            return None, None

    body_headers, body_content = parse_payload(body)

    if isinstance(body_headers, bytes):
        body_headers = body_headers.decode(errors='ignore')
    if isinstance(body_content, bytes):
        body_content = body_content.decode(errors='ignore')

    return body_headers, body_content

if __name__ == "__main__":
    # package start 0201 is cre data
    data = '' # cre data
    data = bytes.fromhex(data)
    headers, body = decrypt(data)
    print("Headers:")
    print(headers)
    print("\nBody:")
    print(body)
