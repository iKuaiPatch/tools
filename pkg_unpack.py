import base64, os, json
from Crypto.Cipher import AES
import hashlib
from passlib.utils.pbkdf2 import pbkdf1
import sys
import gzip

def hasher(algo, data):
    hashes = {'md5': hashlib.md5, 'sha256': hashlib.sha256,
    'sha512': hashlib.sha512}
    h = hashes[algo]()
    h.update(data)

    return h.digest()

# pwd and salt must be bytes objects
def openssl_kdf(algo, pwd, salt, key_size, iv_size):
    if algo == 'md5':
        temp = pbkdf1(pwd, salt, 1, 16, 'md5')
    else:
        temp = b''

    fd = temp    
    while len(fd) < key_size + iv_size:
        temp = hasher(algo, temp + pwd + salt)
        fd += temp

    key = fd[0:key_size]
    iv = fd[key_size:key_size+iv_size]

    # print('salt=' + binascii.hexlify(salt).decode('ascii').upper())
    # print('key=' + binascii.hexlify(key).decode('ascii').upper())
    # print('iv=' + binascii.hexlify(iv).decode('ascii').upper())

    return key, iv

def aes_decrypt(password, ciphertext, salted=False):
    if salted:
        # skip header "Salted__"
        ciphertext = ciphertext[8:]
        salt = ciphertext[:8]

        key_length = 16  # AES-128

        #skip salt
        ciphertext = ciphertext[8:]
    else:
        salt = b''
        key_length = 32  # AES-256
    
    iv_length = 16
    key=None
    iv=None
    key,iv=openssl_kdf(algo="md5",pwd=password,salt=salt,key_size=key_length,iv_size=iv_length)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = plaintext.rstrip(b'\0')
    plaintext = plaintext[:-plaintext[-1]]

    return plaintext

def usage():
    print("Usage: python pkg_unpack.py <input_dir> <output_dir>")
    print("Example: python pkg_unpack.py ./pkgdata ./pkgdata_unpack")
    exit(1)

ext_ikp = [
    {
        "name": "docker-bin",
        "priority": 20,
        "group": "docker-bin",
        "type": "daemon",
        "version": "202102031900",
        "ver_method": "cat /tmp/ikpkg/docker-bin/version",
        "ver_cmp": "noequal",
        "download": [
            "http://packages.ikuai8.com/docker-bin/3/docker-bin_202102031900.x86_64.ikp",
            "https://download.ikuai8.com:32016/plugins/others/docker-bin/3/docker-bin_202102031900.x86_64.ikp",
            "http://pkgdl.ikuai8.com/docker-bin/3/docker-bin_202102031900.x86_64.ikp"
        ],
        "md5": "dc7f031c55b0ee8012cb753d808f64fb",
        "encryption": "aes-128-cbc",
        "secret_key": "354a738f7b2756a848f3b8de541ec58",
        "minimum_size": 69632,
        "timeout_per_request": 600
    },
    {
        "name": "docker",
        "priority": 50,
        "group": "docker",
        "type": "app",
        "version": "1.1.22",
        "ver_method": "cat /tmp/ikpkg/docker/version",
        "ver_cmp": "noequal",
        "download": [
            "http://packages.ikuai8.com/docker/3/docker_1.1.22.gen.ikp",
            "https://download.ikuai8.com:32016/plugins/others/docker/3/docker_1.1.22.gen.ikp",
            "http://pkgdl.ikuai8.com/docker/3/docker_1.1.22.gen.ikp"
        ],
        "md5": "e63edfd1f194278e15d559ceee4849ce",
        "encryption": "aes-128-cbc",
        "secret_key": "354a738f7b2756a848f3b8de541ec57"
    }
]

def main():
    if len(sys.argv) != 3:
        usage()
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    db_path = f'{output_dir}/db'

    if not os.path.exists(db_path):
        os.makedirs(db_path)

    with open(f'{input_dir}/db/.__DB.3.x86_64', 'r') as f:
        ciphertext = f.read()

    password = b'ikupdat-d~#-'
    encrypted_data = base64.b64decode(ciphertext)
    decrypted_data = aes_decrypt(password, encrypted_data, salted=False)
    decrypted_data = decrypted_data.decode('utf-8')
    print(decrypted_data)

    with open(f'{db_path}/db.json', 'w') as f:
        f.write(decrypted_data)

    json_data = json.loads(decrypted_data)
    json_data.extend(ext_ikp)
    for pkg in json_data:
        try:
            password = pkg['secret_key'].encode('utf-8')
            if os.path.exists(f'{input_dir}/{pkg["name"]}.bin.pkg'):
                with open(f'{input_dir}/{pkg["name"]}.bin.pkg', 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = aes_decrypt(password, encrypted_data, salted=True)
                with open(f'{output_dir}/{pkg["name"]}.bin', 'wb') as f:
                    f.write(decrypted_data)
                print(f'Decrypted {pkg["name"]} successfully')
            else:
                print(f'{input_dir}/{pkg["name"]}.bin.pkg not found')
        except Exception as e:
            print(f'Error processing {pkg["name"]}: {e}')
    

    gzip_header = b'\x0A\x1F\x8B\x08\x00'
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            path = os.path.join(root, file)
            with open(path, 'rb') as f:
                file = f.read()
            # find gzip header
            idx = file.find(gzip_header)
            if idx != -1:
                pkgname = os.path.basename(path).split('.')[0]
                os.mkdir(f'{output_dir}/{pkgname}')
                with open(f'{output_dir}/{pkgname}/install.sh', 'wb') as f:
                    f.write(file[:idx])
                data = file[idx:]
                magic = b"\x1f\x8b"
                pos = data.find(magic)
                if pos == -1:
                    with open(f'{output_dir}/{pkgname}/{pkgname}', 'wb') as f:
                        f.write(data)
                    print("gzip header not found")
                    continue
                try:
                    print(f'Extracting {pos} {pkgname}...')
                    data = gzip.decompress(data[pos:])
                    with open(f'{output_dir}/{pkgname}/{pkgname}.tar', 'wb') as f:
                        f.write(data)
                except Exception as e:
                    print(f'Error decompressing {pkgname}: {e}')
                    with open(f'{output_dir}/{pkgname}/{pkgname}', 'wb') as f:
                        f.write(data)

if __name__ == '__main__':
    main()
