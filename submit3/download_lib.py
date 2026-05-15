
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
libproto_v4 = config.get("GLOBAL", "libproto_v4_ver", fallback=None) # dpiv4

libaudit = config.get("GLOBAL", "libaudit_ver", fallback=None) # im
libaudit_v4 = config.get("GLOBAL", "libaudit_v4_ver", fallback=None) # imv4

libdomain_ver = config.get("GLOBAL", "libdomain_ver", fallback=None) # domain
libdomain2_ver = config.get("GLOBAL", "libdomain2_ver", fallback=None) # domain2

libvcache_ver = config.get("GLOBAL", "libvcache_ver", fallback=None) # cache service

libcrts = config.get("GLOBAL", "libcrts_ver", fallback=None) # crts

patch_url = 'https://patch-src.ikuai8.com:2000/lib/'
patch_url2 = 'https://patch.ikuai8.com/lib/'

def has_version(version):
    return version is not None and str(version).strip() != ""


file_specs = [
    ("IKprotocol", libproto),
    ("IKprotocolMINI", libproto),
    ("IKprotocol", libproto_v4),
    ("IKprotocolMINI", libproto_v4),
    ("IKl4dpi", libproto4_ver),
    ("IKaudit", libaudit),
    ("IKauditX", libaudit),
    ("IKaudit", libaudit_v4),
    ("IKauditX", libaudit_v4),
    ("IKdomain", libdomain_ver),
    ("IKdomain2", libdomain_ver),
    ("IKdomain", libdomain2_ver),
    ("IKdomain2", libdomain2_ver),
    ("IKvcache2", libvcache_ver),
    ("IKcrts", libcrts),
]

files = []
for prefix, version in file_specs:
    if has_version(version):
        files.append(f"{prefix}_{version}.lib")
    else:
        print(f"Skip {prefix}: empty version")

headers = {
    'X-Firmware': 'IK-RouterOS',
    'X-Router-Ver': '4.0.210',
    'X-GWID': '',
    'X-Build-Date': '202604161034',
    'X-Sysbit': 'x64',
    'X-Oemname': '',
    'X-Overseas': '',
    'X-Edition-Type': 'Enterprise'
}

lib_dir = Path("lib")
lib_dir.mkdir(exist_ok=True)

for file in files:
    downloaded = False
    for base_url in (patch_url, patch_url2):
        try:
            print("Downloading:", file, "from", base_url)
            r = requests.get(base_url + file, stream=True, timeout=30, headers=headers, verify=False)
            if r.status_code != 200:
                print("Failed:", file, "from", base_url, "status", r.status_code)
                continue
            if 'text/html' in r.headers.get('Content-Type', ''):
                print("Failed (HTML content):", file, "from", base_url)
                continue

            with open(lib_dir / file, "wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)

            downloaded = True
            break
        except requests.RequestException as e:
            print("Request error:", file, "from", base_url, e)

    if not downloaded:
        print("Failed to download from all sources:", file)

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

