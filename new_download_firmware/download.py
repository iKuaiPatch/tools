#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import secrets
import ssl
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SIGN_URL_API = "https://devapi.ikuai8.com/firmware/sign-url"
VERSION_ALL_API = "https://devapi.ikuai8.com/firmware/version-all"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CA = SCRIPT_DIR / "mtls" / "ca.crt"
DEFAULT_CERT = SCRIPT_DIR / "mtls" / "client.crt"
DEFAULT_KEY = SCRIPT_DIR / "mtls" / "client.key"
MTLS_VERIFY_SERVER = False
DEVICE_GWID = secrets.token_hex(16)
DEVICE_SECRET = DEVICE_GWID[-10:]
DEFAULT_DEVICE_KEY = "x86"

device_map = {
    "x86": {
        "platform": "x86",
        "system": "community",
        "model_type": "X86",
    },
    "x86ent": {
        "platform": "x86",
        "system": "enterprise",
        "model_type": "X86ENT",
    },
    "a220pro": {
        "platform": "arm",
        "system": "community",
        "model_type": "A220PRO",
    },
    "m100": {
        "platform": "arm",
        "system": "community",
        "model_type": "M100",
    },
    "m200": {
        "platform": "arm",
        "system": "community",
        "model_type": "M200",
    },
    "m5s": {
        "platform": "arm",
        "system": "community",
        "model_type": "M5S",
    },
    "m10s": {
        "platform": "arm",
        "system": "community",
        "model_type": "M10S",
    },
    "m60": {
        "platform": "arm",
        "system": "community",
        "model_type": "M60",
    },
    "m360x": {
        "platform": "arm",
        "system": "community",
        "model_type": "M360X",
    },
    "a50": {
        "platform": "arm",
        "system": "community",
        "model_type": "A50",
    },
    "a50-p": {
        "platform": "arm",
        "system": "community",
        "model_type": "A50-P",
    },
    "a100-p": {
        "platform": "arm",
        "system": "community",
        "model_type": "A100-P",
    },
    "m08": {
        "platform": "arm",
        "system": "community",
        "model_type": "M08",
    },
    "a160": {
        "platform": "arm",
        "system": "community",
        "model_type": "A160",
    },
    "q3s": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3S",
    },
    "y3000g-pro": {
        "platform": "arm",
        "system": "community",
        "model_type": "Y3000G-PRO",
    },
    "c3000": {
        "platform": "arm",
        "system": "community",
        "model_type": "C3000",
    },
    "q3000": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3000",
    },
    "q3600": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3600",
    },
    "q6000": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q6000",
    },
    "m1": {
        "platform": "mips",
        "system": "community",
        "model_type": "M1",
    },
    "m2": {
        "platform": "mips",
        "system": "community",
        "model_type": "M2",
    },
    "m5": {
        "platform": "mips",
        "system": "community",
        "model_type": "M5",
    },
    "m50": {
        "platform": "mips",
        "system": "community",
        "model_type": "M50",
    },
    "g05": {
        "platform": "mips",
        "system": "community",
        "model_type": "G05",
    },
    "a120": {
        "platform": "mips",
        "system": "community",
        "model_type": "A120",
    },
    "a125": {
        "platform": "mips",
        "system": "community",
        "model_type": "A125",
    },
    "a130": {
        "platform": "mips",
        "system": "community",
        "model_type": "A130",
    },
    "a135s": {
        "platform": "mips",
        "system": "community",
        "model_type": "A135S",
    },
    "a139s": {
        "platform": "mips",
        "system": "community",
        "model_type": "A139S",
    },
    "q50": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q50",
    },
    "q80": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q80",
    },
    "q85": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q85",
    },
    "q90": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q90",
    },
    "q1800": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q1800",
    },
    "q1800l": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q1800L",
    },
    "c20": {
        "platform": "mips",
        "system": "community",
        "model_type": "C20",
    },
    "c25-g": {
        "platform": "mips",
        "system": "community",
        "model_type": "C25-G",
    },
    "c50": {
        "platform": "mips",
        "system": "community",
        "model_type": "C50",
    },
    "c90": {
        "platform": "mips",
        "system": "community",
        "model_type": "C90",
    },
    "x86_oem": {
        "platform": "x86-64",
        "system": "community",
        "model_type": "X86_oem",
    },
    "m1_oem": {
        "platform": "mips",
        "system": "community",
        "model_type": "M1_oem",
    },
    "m100_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M100_oem",
    },
    "m200_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M200_oem",
    },
    "m5s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M5S_oem",
    },
    "m10s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M10S_oem",
    },
    "a160_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "A160_oem",
    },
    "q3s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3S_oem",
    },
    "q3000_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3000_oem",
    },
    "q6000_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q6000_oem",
    },
    "x64free": {
        "platform": "x86-64",
        "system": "community",
        "model_type": "X86",
    },
    "x64ent": {
        "platform": "x86-64",
        "system": "enterprise",
        "model_type": "X86ENT",
    },
}


@dataclass
class DeviceInfo:
    gwid: str
    platform: str
    secret: str
    system: str
    model_type: str


class TLSAdapter(HTTPAdapter):
    def __init__(self, ssl_context: ssl.SSLContext, **kwargs: Any) -> None:
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["ssl_context"] = self.ssl_context
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)


def debug(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        text = message % args if args else message
        print(f"[DEBUG] {text}", file=sys.stderr, flush=True)


def md5_file(path: Path) -> str | None:
    if not path.exists():
        return None

    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calc_sign(params: Mapping[str, str], secret: str, debug_enabled: bool) -> str:
    keys = sorted(key for key, value in params.items() if value)
    raw = "&".join(f"{key}={params[key]}" for key in keys)
    debug(debug_enabled, "sign string: %s", raw)
    sign = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    debug(debug_enabled, "sign result: %s", sign)
    return sign


def rand10() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(10))


def build_device_info(device_name: str) -> DeviceInfo:
    current_device = device_map.get(device_name.lower())
    if current_device is None:
        available = ", ".join(sorted(device_map))
        raise ValueError(f"unknown device: {device_name}; available devices: {available}")

    return DeviceInfo(
        gwid=DEVICE_GWID,
        platform=current_device["platform"],
        secret=DEVICE_SECRET,
        system=current_device["system"],
        model_type=current_device["model_type"],
    )


def validate_device_info(device: DeviceInfo, mode: str) -> None:
    missing = []
    if not device.gwid:
        missing.append("gwid")
    if not device.secret:
        missing.append("secret")
    if not device.model_type:
        missing.append("model_type")
    if mode != "Version_all" and not device.platform:
        missing.append("platform")
    if mode != "Version_all" and not device.system:
        missing.append("system")

    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"missing device info: {joined}")


def new_insecure_session() -> requests.Session:
    session = requests.Session()
    session.verify = False
    return session


def new_mtls_session(ca_file: Path, cert_file: Path, key_file: Path) -> requests.Session:
    if MTLS_VERIFY_SERVER:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    session = requests.Session()
    session.verify = str(ca_file) if MTLS_VERIFY_SERVER else False
    session.mount("https://", TLSAdapter(context))
    return session


def request_api_json(
    session: requests.Session,
    method: str,
    url: str,
    headers: Mapping[str, str] | None,
    debug_enabled: bool,
) -> tuple[int, dict[str, Any]]:
    debug(debug_enabled, "%s %s", method, url)
    if headers:
        for key, value in headers.items():
            debug(debug_enabled, "header %s: %s", key, value)

    try:
        response = session.request(
            method=method,
            url=url,
            headers=dict(headers or {}),
            data="" if method == "POST" else None,
            allow_redirects=True,
            timeout=(10, 20),
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"request failed: {exc}") from exc

    debug(debug_enabled, "response [%d]: %s", response.status_code, response.text)

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{url} JSON decode error: {exc}") from exc
    return response.status_code, payload


def parse_api_data(payload: Mapping[str, Any], label: str) -> dict[str, Any]:
    code = payload.get("code")
    if code != 0:
        raise RuntimeError(f"{label} API error: code={code} message={payload.get('message', '')}")

    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} API response missing data")
    return data


def request_sign_url(
    session: requests.Session,
    device: DeviceInfo,
    firmware_name: str,
    nonce: str,
    debug_enabled: bool,
) -> dict[str, Any]:
    params = {
        "X-Device-Platform": device.platform,
        "X-Firmware-Name": firmware_name,
        "X-Gw-Id": device.gwid,
        "X-Nonce": nonce,
        "X-System-Version": device.system,
        "X-Model-Type": device.model_type,
    }
    sign = calc_sign(params, device.secret, debug_enabled)
    headers = {**params, "X-Sign": sign}

    status_code, payload = request_api_json(session, "POST", SIGN_URL_API, headers, debug_enabled)
    if status_code != 200:
        raise RuntimeError(f"sign-url HTTP error: {status_code}, body: {json.dumps(payload, ensure_ascii=False)}")
    return parse_api_data(payload, "sign-url")


def request_version_all(
    session: requests.Session,
    device: DeviceInfo,
    nonce: str,
    debug_enabled: bool,
) -> dict[str, Any]:
    params = {
        "X-Device-Platform": device.model_type,
        "X-Gw-Id": device.gwid,
        "X-Nonce": nonce,
    }
    sign = calc_sign(params, device.secret, debug_enabled)
    headers = {**params, "X-Sign": sign}

    status_code, payload = request_api_json(session, "GET", VERSION_ALL_API, headers, debug_enabled)
    if status_code != 200:
        raise RuntimeError(f"version-all HTTP error: {status_code}, body: {json.dumps(payload, ensure_ascii=False)}")
    return parse_api_data(payload, "version-all")


def download_file(
    session: requests.Session,
    url: str,
    headers: Mapping[str, str] | None,
    output_file: Path,
    debug_enabled: bool,
) -> None:
    debug(debug_enabled, "download url: %s", url)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(prefix=f"{output_file.name}.", suffix=".part", dir=str(output_file.parent))
    os.close(temp_fd)
    temp_path = Path(temp_name)

    last_percent = -1
    try:
        with session.get(
            url,
            headers=dict(headers or {}),
            stream=True,
            allow_redirects=True,
            timeout=(30, 3600),
        ) as response:
            if response.status_code != 200:
                raise RuntimeError(f"HTTP error: {response.status_code}")

            total = int(response.headers.get("Content-Length", "0") or "0")
            downloaded = 0

            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    downloaded += len(chunk)

                    if total > 0:
                        percent = downloaded * 100 // total
                        if percent != last_percent:
                            last_percent = percent
                            print(f"{percent}%", file=sys.stderr, flush=True)

            if total > 0 and last_percent < 100:
                print("100%", file=sys.stderr, flush=True)

        temp_path.replace(output_file)
    except requests.RequestException as exc:
        temp_path.unlink(missing_ok=True)
        raise RuntimeError(f"download request failed: {exc}") from exc
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def run_version_all(args: argparse.Namespace, device: DeviceInfo, output_file: Path) -> int:
    local_md5 = md5_file(output_file) or ""
    if local_md5:
        debug(args.debug, "local file checksum: %s", local_md5)

    nonce = rand10()
    session = new_insecure_session()
    data = request_version_all(session, device, nonce, args.debug)

    debug(args.debug, "version-all data: %s", json.dumps(data, ensure_ascii=False))

    debug(
        args.debug,
        "versionType=%s isBeta=%s md5=%s",
        data.get("versionType"),
        data.get("isBeta"),
        data.get("md5"),
    )

    remote_md5 = str(data.get("md5") or "")
    if local_md5 and remote_md5 and local_md5.lower() == remote_md5.lower():
        return 0

    file_url = data.get("fileUrl")
    if not file_url:
        raise RuntimeError("API response missing fileUrl")

    download_file(session, str(file_url), None, output_file, args.debug)
    return 0


def run_firmware(args: argparse.Namespace, device: DeviceInfo, firmware_name: str, output_file: Path) -> int:
    local_md5 = md5_file(output_file) or ""
    if local_md5:
        debug(args.debug, "local file checksum: %s", local_md5)

    nonce = rand10()
    session = new_insecure_session()
    data = request_sign_url(session, device, firmware_name, nonce, args.debug)

    if data.get("md5Verified") and data.get("md5Match"):
        debug(args.debug, "already up to date (md5 match, ossMD5=%s)", data.get("ossMD5"))
        return 0

    sign_url = data.get("signUrl")
    token = data.get("token")
    if not sign_url:
        raise RuntimeError("sign-url API response missing signUrl")
    if not token:
        raise RuntimeError("sign-url API response missing token")

    mtls_session = new_mtls_session(Path(args.ca_file), Path(args.cert_file), Path(args.key_file))
    headers = {
        "X-Auth-Token": str(token),
        "X-Gw-Id": device.gwid,
    }
    download_file(mtls_session, str(sign_url), headers, output_file, args.debug)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python firmware downloader compatible with download.lua.lua",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug output")
    parser.add_argument("--device", default=DEFAULT_DEVICE_KEY, help="device profile from device_map")
    parser.add_argument("target", help="firmware name, or Version_all")
    parser.add_argument("output_file", help="output file path")
    parser.add_argument("--ca-file", default=str(DEFAULT_CA), help="CA certificate for mTLS download")
    parser.add_argument("--cert-file", default=str(DEFAULT_CERT), help="client certificate for mTLS download")
    parser.add_argument("--key-file", default=str(DEFAULT_KEY), help="client private key for mTLS download")
    return parser.parse_args()


def main() -> int:
    random.seed()
    args = parse_args()
    output_file = Path(args.output_file)
    mode = args.target

    try:
        device = build_device_info(args.device)
        validate_device_info(device, mode)
        debug(
            args.debug,
            "device: gwid=%s platform=%s system=%s modelType=%s",
            device.gwid,
            device.platform,
            device.system,
            device.model_type,
        )

        if mode == "Version_all":
            return run_version_all(args, device, output_file)
        return run_firmware(args, device, mode, output_file)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        if mode == "Version_all":
            if "missing fileUrl" in str(exc):
                return 3
            if "HTTP error" in str(exc):
                return 4
            return 2
        if "HTTP error" in str(exc):
            return 3
        return 2


if __name__ == "__main__":
    sys.exit(main())
