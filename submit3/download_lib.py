
# https://patch-src.ikuai8.com:2000/lib/IKcrts_10.lib
# https://patch-src.ikuai8.com:2000/lib/IKprotocol_2.0.436.lib
# https://patch-src.ikuai8.com:2000/lib/IKauditX_2.1.17.lib

# https://download.ikuai8.com/submit3x/Version_all
# https://download.ikuai8.com/submit3x/white_wifi_filter.txt
# https://download.ikuai8.com/plugins/config3x.json

import configparser
import requests
import io, os
import struct, gzip
from pathlib import Path

requests.packages.urllib3.disable_warnings()

url = "https://download.ikuai8.com/submit3x/Version_all"
resp = requests.get(url, timeout=10)
resp.encoding = 'utf-8'

with open("Version_all", "w", encoding="utf-8") as f:
    f.write(resp.text)

text = resp.text

config = configparser.ConfigParser()
config.read_file(io.StringIO(text))

# for section in config.sections():
#     print("Section:", section)
#     for key, value in config.items(section):
#         print(f"  {key} = {value}")

libproto = config.get("GLOBAL", "libproto_ver", fallback=None) # dpi
libproto4_ver = config.get("GLOBAL", "libproto4_ver", fallback=None) # dpi4

libaudit = config.get("GLOBAL", "libaudit_ver", fallback=None) # im

libdomain_ver = config.get("GLOBAL", "libdomain_ver", fallback=None) # domain
libdomain2_ver = config.get("GLOBAL", "libdomain2_ver", fallback=None) # domain2

libvcache_ver = config.get("GLOBAL", "libvcache_ver", fallback=None) # cache service

libcrts = config.get("GLOBAL", "libcrts_ver", fallback=None) # crts

patch_url = 'https://patch-src.ikuai8.com:2000/lib/'
libproto_file = f"IKprotocol_{libproto}.lib"
libproto_mini_file = f"IKprotocolMINI_{libproto}.lib"
libproto4_file = f"IKl4dpi_{libproto4_ver}.lib"

libaudit_file = f"IKaudit_{libaudit}.lib"
libauditx_file = f"IKauditX_{libaudit}.lib"

libdomain_file = f"IKdomain_{libdomain_ver}.lib"
libdomain2_file = f"IKdomain2_{libdomain_ver}.lib"

libdomain_file2 = f"IKdomain_{libdomain2_ver}.lib"
libdomain2_file2 = f"IKdomain2_{libdomain2_ver}.lib"

libvcache_file = f"IKvcache2_{libvcache_ver}.lib"

libcrts_file = f"IKcrts_{libcrts}.lib"

files = [
    libproto_file,
    libproto_mini_file,
    libproto4_file,
    libaudit_file,
    libauditx_file,
    libdomain_file,
    libdomain2_file,
    libdomain_file2,
    libdomain2_file2,
    libvcache_file,
    libcrts_file,
]

for file in files:
    print("Downloading:", file)
    r = requests.get(patch_url + file, stream=True, timeout=30, verify=False)
    if r.status_code != 200:
        print("Failed to download:", file, r.status_code)
        continue
    if 'text/html' in r.headers.get('Content-Type', ''):
        print("Failed to download (HTML content):", file)
        continue
    with open(f'lib/{file}', "wb") as f:
        for chunk in r.iter_content(8192):
            f.write(chunk)

lib_dir = Path("lib")
lib_dir.mkdir(exist_ok=True)

for path in lib_dir.glob("*.lib"):
    try:
        basename = path.stem
        out_dir = lib_dir / basename
        out_dir.mkdir(exist_ok=True)

        with path.open("rb") as f:
            headlen = struct.unpack(">I", f.read(4))[0]

            header_data = f.read(headlen)
            header_json = gzip.decompress(
                b"\x1f\x8b\x08\x00\x6f\x9b\x4b\x59\x02\x03" + header_data
            )

            with (out_dir / "header_info.json").open("wb") as ff:
                ff.write(header_json)

            file_data = f.read()
            tar_data = gzip.decompress(file_data)

            with (out_dir / f"{basename}.tar").open("wb") as ff:
                ff.write(tar_data)

    except Exception as e:
        print("Error processing file:", path.name, e)

