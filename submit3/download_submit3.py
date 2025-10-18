import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import subprocess, shutil
import os, sys, re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ikluajit

ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

string_pattern = re.compile(r'(["\'])(.*?)(?<!\\)\1', re.DOTALL)

def process_lua_file(input_path, output_path=None):
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    def replacer(match):
        quote = match.group(1)
        string_content = match.group(2)
        return convert_lua_string(string_content)

    new_content = string_pattern.sub(replacer, content)

    if not output_path:
        output_path = input_path

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

def safe_lua_multiline(s):
    """Generate a Lua long string, avoiding internal conflicts with ]]."""
    level = 0
    while f']{"="*level}]' in s:
        level += 1
    
    s = re.sub(r'(?<!\\)\\n', r'\n', s)
    s = re.sub(r'(?<!\\)\\t', r'\t', s)
    
    s = re.sub(r'(?<!\\)\\\\n', r'\\n', s)
    s = re.sub(r'(?<!\\)\\\\t', r'\\t', s)

    s = s.replace('\\"', '"')

    if '\n' in s and not s.startswith('\n'):
        s = '\n' + s
    # if not s.endswith('\n'):
    #     s += '\n'
    return f'[{("="*level)}[{s}]{("="*level)}]'

def convert_lua_string(s: str):
    """
    Convert a Lua string:
    - If it contains \n or \t, convert to long string [[...]] style
    - Otherwise, keep as quoted string and escape " and \
    """
    non_printable = s.replace('\\n', '\n').replace('\\t', '\t').replace('\r', '').strip()
    if ('\\n' in s or '\\t' in s or '\\"' in s) and non_printable != '' and len(non_printable) > 20:
        return safe_lua_multiline(s)

    return f'"{s}"'

class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['ssl_context'] = self.ssl_context
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="cert/ca.pem")
ssl_ctx.set_ciphers('ALL:@SECLEVEL=0')
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
ssl_ctx.load_cert_chain(certfile="cert/client.pem", keyfile="cert/client.key")

session = requests.Session()
session.mount("https://", SSLAdapter(ssl_context=ssl_ctx))

url = "https://download.ikuai8.com:32015/submit3x/submit3"
response = session.get(url, timeout=10, verify=False)
print(f"Response status code: {response.status_code}")

shutil.rmtree('lua', ignore_errors=True)
os.makedirs('lua', exist_ok=True)

with open("lua/submit3", "wb") as f:
    f.write(response.content)

ikluajit.decrypt_lua('lua/submit3', 'lua/submit3.luac')

subprocess.run(["luajit-decompiler-v2.exe", "lua/submit3.luac", "-m", "-o", "lua"], check=True)
process_lua_file('lua/submit3.lua')
print("Decompiled and processed Lua file saved to lua/submit3.lua")

deobf = {
    "var_0_0": "string_match",
    "var_0_1": "submit_patch_path",
    "var_0_2": "plugins_path",
    "var_0_3": "libproto_path",
    "var_0_4": "ik_hosts_path",
    "var_0_5": "posix_r",
    "var_0_6": "cjson",
    "var_0_7": "bit",
    "var_0_8": "ffi",
    "var_0_9": "C",
    "var_0_10": "string_format",
    "var_0_11": "libssl",
    "var_0_12": "ffi_sizeof",
    "var_0_13": "uint32_array_type",
    "var_0_14": "uint64_array_type",
    "var_0_15": "int_array_type",
    "var_0_16": "char_array_type",
    "var_0_17": "dup2_flag",
    "var_0_19": "functions",
    "var_0_20": "args",
    "var_0_21": "release_info",
    "var_0_22": "all_version",
    "var_0_26": "access_flag",
    "var_0_28": "flcok_flag_1",
    "var_0_29": "flcok_flag_2",
    "var_0_30": "flcok_flag",
    "var_0_31": "kill_signal",
    "var_0_33": "ca_file_exist",
    "var_0_34": "use_ipv4",
    "var_0_35": "char_array_size",
    "var_0_36": "char_array",
    "var_0_37": "timespec",
    "var_0_38": "timeval",
    "var_0_39": "AES_BLOCK_SIZE",
    "var_0_40": "AES_cbc_encrypt",
    "var_0_41": "AES_set_decrypt_key",
    "var_0_42": "AES_set_encrypt_key",
    "var_0_43": "aes_key",
    "var_0_44": "AES_DECRYPT",
    "var_0_45": "AES_ENCRYPT",
    "var_0_46": "posix"
}

with open('lua/submit3.lua', 'r', encoding='utf-8') as f:
    content = f.read()

for k, v in deobf.items():
    if v:
        pattern = re.compile(r'\b' + re.escape(k) + r'\b')
        content = pattern.sub(v, content)
    else:
        print(f'Warning: {k} has no replacement value')

with open('lua/submit3.lua', 'w', encoding='utf-8') as f:
    f.write(content)