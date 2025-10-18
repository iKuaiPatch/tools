import requests
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import gzip

CONFIG_URL = "https://download.ikuai8.com/plugins/config3x.json"
PLUGINS_URL = "https://download.ikuai8.com/plugins"

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=16, iv_len=16):
    """OpenSSL EVP_BytesToKey 用 MD5 派生 key + iv"""
    m = b''
    prev = b''
    while len(m) < (key_len + iv_len):
        prev = hashlib.md5(prev + password + salt).digest()
        m += prev
    return m[:key_len], m[key_len:key_len + iv_len]

def aes128cbc_decrypt_openssl_compat(password_str, infile, outfile):
    pw = password_str.encode('utf-8')
    with open(infile, 'rb') as f:
        data = f.read()

    if data.startswith(b"Salted__"):
        salt = data[8:16]
        ciphertext = data[16:]
        key, iv = _evp_bytes_to_key(pw, salt, 16, 16)
    else:
        if len(data) < 16:
            raise ValueError("input too short to contain IV")
        iv = data[:16]
        ciphertext = data[16:]
        key = pw.ljust(16, b"\0")[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as e:
        raise ValueError("decrypt failed, padding error. wrong password or wrong file format") from e

    with open(outfile, 'wb') as f:
        f.write(plaintext)


def md5sum(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def download_file(url, filepath):
    r = requests.get(url, stream=True, timeout=30)
    r.raise_for_status()
    with open(filepath, "wb") as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)

def main(key, outdir="ikp"):
    os.makedirs(outdir, exist_ok=True)

    resp = requests.get(CONFIG_URL, timeout=10)
    with open("config3x.json", "wb") as f:
        f.write(resp.content)
    cfg = resp.json()

    for mode in ("release", "test"):
        if mode not in cfg:
            continue
        for plugin, archs in cfg[mode].items():
            if plugin == "GWIDS":  # 跳过 GWIDS 列表
                continue
            for arch, (md5_expect, filename) in archs.items():
                url = f"{PLUGINS_URL}/{mode}/{plugin}/3/{filename}"
                tmpfile = os.path.join(outdir, f"{mode}_{plugin}_{arch}.ikp")
                decfile = os.path.join(outdir, f"{mode}_{plugin}_{arch}.x")

                print("Downloading:", url)
                try:
                    download_file(url, tmpfile)
                except Exception as e:
                    print("Download failed:", e)
                    continue

                if md5sum(tmpfile) != md5_expect:
                    print("MD5 mismatch, removing:", tmpfile)
                    os.remove(tmpfile)
                    continue

                try:
                    aes128cbc_decrypt_openssl_compat(key, tmpfile, decfile)
                    print("Decrypted ->", decfile)
                except Exception as e:
                    print("Decrypt failed:", e)

    gzip_header = b'\x0A\x1F\x8B\x08\x00'
    for root, dirs, files in os.walk(outdir):
        for file in files:
            if not file.endswith('.x'):
                continue
            path = os.path.join(root, file)
            with open(path, 'rb') as f:
                file = f.read()
            # find gzip header
            idx = file.find(gzip_header)
            if idx != -1:
                pkgname = os.path.basename(path).split('.')[0]
                os.mkdir(f'{outdir}/{pkgname}')
                with open(f'{outdir}/{pkgname}/install.sh', 'wb') as f:
                    f.write(file[:idx])
                data = file[idx:]
                magic = b"\x1f\x8b"
                pos = data.find(magic)
                if pos == -1:
                    with open(f'{outdir}/{pkgname}/{pkgname}', 'wb') as f:
                        f.write(data)
                    print("gzip header not found")
                    continue
                try:
                    print(f'Extracting {pos} {pkgname}...')
                    data = gzip.decompress(data[pos:])
                    with open(f'{outdir}/{pkgname}/{pkgname}.tar', 'wb') as f:
                        f.write(data)
                except Exception as e:
                    print(f'Error decompressing {pkgname}: {e}')
                    with open(f'{outdir}/{pkgname}/{pkgname}', 'wb') as f:
                        f.write(data)

if __name__ == "__main__":
    KEY = "ik.cdn.cn"  # 解密密钥
    main(KEY)
