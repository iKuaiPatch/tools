#!/usr/bin/luajit
local ffi = require("ffi")
local cjson = require("cjson")
local load_config = require("iklua.utils.load_config")

----------------------------------------------------------------
-- FFI declarations
----------------------------------------------------------------
local crypto = ffi.load("libcrypto.so.1.0.0")
local libcurl = ffi.load("libcurl.so.4")

ffi.cdef[[
/* OpenSSL HMAC */
typedef unsigned char uchar;
typedef unsigned int  uint;
typedef unsigned long size_t;
typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_sha256(void);
uchar *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
            const uchar *d, size_t n, uchar *md, uint *md_len);

/* libcurl */
struct curl_slist { char *data; struct curl_slist *next; };
void *curl_easy_init();
int   curl_easy_setopt(void *curl, int option, ...);
int   curl_easy_getinfo(void *curl, int option, ...);
int   curl_easy_perform(void *curl);
void  curl_easy_cleanup(void *curl);
struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data);
void  curl_slist_free_all(struct curl_slist *list);

/* stdio */
void  *fopen(const char *path, const char *mode);
int    fclose(void *fp);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *fp);
]]

-- curl option constants
local CURLOPTTYPE_LONG          = 0
local CURLOPTTYPE_OBJECTPOINT   = 10000
local CURLOPTTYPE_FUNCTIONPOINT = 20000

local CURLOPT_WRITEDATA          = CURLOPTTYPE_OBJECTPOINT + 1
local CURLOPT_URL                = CURLOPTTYPE_OBJECTPOINT + 2
local CURLOPT_POSTFIELDS         = CURLOPTTYPE_OBJECTPOINT + 15
local CURLOPT_HTTPHEADER         = CURLOPTTYPE_OBJECTPOINT + 23
local CURLOPT_WRITEFUNCTION      = CURLOPTTYPE_FUNCTIONPOINT + 11
local CURLOPT_PROGRESSFUNCTION   = CURLOPTTYPE_FUNCTIONPOINT + 56
local CURLOPT_SSLCERT            = CURLOPTTYPE_OBJECTPOINT + 25
local CURLOPT_CAINFO             = CURLOPTTYPE_OBJECTPOINT + 65
local CURLOPT_SSLKEY             = CURLOPTTYPE_OBJECTPOINT + 87
local CURLOPT_VERBOSE            = CURLOPTTYPE_LONG + 41
local CURLOPT_NOPROGRESS         = CURLOPTTYPE_LONG + 43
local CURLOPT_POST               = CURLOPTTYPE_LONG + 47
local CURLOPT_FOLLOWLOCATION     = CURLOPTTYPE_LONG + 52
local CURLOPT_SSL_VERIFYPEER     = CURLOPTTYPE_LONG + 64
local CURLOPT_SSL_VERIFYHOST     = CURLOPTTYPE_LONG + 81
local CURLOPT_CONNECTTIMEOUT     = CURLOPTTYPE_LONG + 78
local CURLOPT_TIMEOUT            = CURLOPTTYPE_LONG + 13 
local CURLINFO_RESPONSE_CODE     = 0x200000 + 2

-- SSL 证书路径（根据实际部署路径修改）
local SSL_CAINFO  = "/etc/ssl/mtls/ca.crt"
local SSL_CERT    = "/etc/ssl/mtls/client.crt"
local SSL_KEY     = "/etc/ssl/mtls/client.key"

local int32  = ffi.new("int[1]")
local uint64 = ffi.new("uint64_t[1]")

----------------------------------------------------------------
-- 参数解析: download.lua [-d] <firmware_name> <output_file>
-- -d: 开启调试输出
----------------------------------------------------------------
local DEBUG   = false
local posargs = {}
for i = 1, #arg do
	if arg[i] == "-d" then
		DEBUG = true
	else
		posargs[#posargs + 1] = arg[i]
	end
end

local function dbg(fmt, ...)
	if DEBUG then
		io.stderr:write("[DEBUG] " .. string.format(fmt, ...) .. "\n")
	end
end

----------------------------------------------------------------
-- libcurl helpers
----------------------------------------------------------------

local DATA_BUFFER = ""

local function write_data_cb(ptr, size, nmemb, _)
	local bytes = size * nmemb
	DATA_BUFFER = DATA_BUFFER .. ffi.string(ptr, bytes)
	return bytes
end
local write_data_ptr = ffi.cast("size_t (*)(char *, size_t, size_t, void *)", write_data_cb)

local function setopt(curl, opt, val)
	if type(val) == "number" then
		uint64[0] = val
		return libcurl.curl_easy_setopt(curl, opt, uint64[0])
	else
		return libcurl.curl_easy_setopt(curl, opt, val)
	end
end

local function make_slist(headers)
	local slist = nil
	for k, v in pairs(headers) do
		slist = libcurl.curl_slist_append(slist, k .. ": " .. v)
	end
	return slist
end

----------------------------------------------------------------
-- 下载进度回调
-- 将进度百分比输出到 stdout, shell 可通过管道或重定向获取
-- 输出格式: "45%\n" (整数百分比，值变化时才输出)
----------------------------------------------------------------
local PROGRESS_LAST = -1

local function progress_cb(_, dltotal, dlnow, _, _)
	if dltotal > 0 then
		local pct = math.floor(dlnow / dltotal * 100)
		if pct ~= PROGRESS_LAST then
			PROGRESS_LAST = pct
			io.stderr:write(string.format("%d%%\n", pct))
			io.stderr:flush()
		end
	end
	return 0
end
local progress_cb_ptr = ffi.cast("int (*)(void *, double, double, double, double)", progress_cb)

local function dbg_curl_cmd(method, url, headers)
	if not DEBUG then return end
	local parts = {"curl", "-v", "-X", method}
	if headers then
		for k, v in pairs(headers) do
			parts[#parts + 1] = string.format("-H '%s: %s'", k, v)
		end
	end
	if method == "POST" then
		parts[#parts + 1] = "-d ''"
	end
	parts[#parts + 1] = string.format("'%s'", url)
	dbg("curl cmd: %s", table.concat(parts, " "))
end

----------------------------------------------------------------
-- HTTP functions
----------------------------------------------------------------

-- HTTP POST, 返回 body 到内存
local function http_post(url, headers)
	dbg_curl_cmd("POST", url, headers)
	DATA_BUFFER = ""
	local curl = libcurl.curl_easy_init()
	if curl == nil then return nil, "curl init failed" end

	local slist = headers and make_slist(headers) or nil

	setopt(curl, CURLOPT_URL, url)
	setopt(curl, CURLOPT_POST, 1)
	setopt(curl, CURLOPT_POSTFIELDS, "")
	setopt(curl, CURLOPT_WRITEFUNCTION, write_data_ptr)
	setopt(curl, CURLOPT_FOLLOWLOCATION, 1)
	setopt(curl, CURLOPT_NOPROGRESS, 1)
	setopt(curl, CURLOPT_SSL_VERIFYPEER, 0)
	setopt(curl, CURLOPT_SSL_VERIFYHOST, 0)
	setopt(curl, CURLOPT_CONNECTTIMEOUT,10)
	setopt(curl, CURLOPT_TIMEOUT,20)
	if slist then setopt(curl, CURLOPT_HTTPHEADER, slist) end
	if DEBUG then setopt(curl, CURLOPT_VERBOSE, 1) end

	local res = libcurl.curl_easy_perform(curl)
	local http_code = 0
	if res == 0 then
		libcurl.curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, int32)
		http_code = int32[0]
	end

	if slist then libcurl.curl_slist_free_all(slist) end
	libcurl.curl_easy_cleanup(curl)

	if res ~= 0 then
		return nil, string.format("curl perform failed: code %d", res)
	end
	return http_code, DATA_BUFFER
end

-- HTTP GET, 返回 body 到内存
local function http_get(url, headers)
	dbg_curl_cmd("GET", url, headers)
	DATA_BUFFER = ""
	local curl = libcurl.curl_easy_init()
	if curl == nil then return nil, "curl init failed" end

	local slist = headers and make_slist(headers) or nil

	setopt(curl, CURLOPT_URL, url)
	setopt(curl, CURLOPT_WRITEFUNCTION, write_data_ptr)
	setopt(curl, CURLOPT_FOLLOWLOCATION, 1)
	setopt(curl, CURLOPT_NOPROGRESS, 1)
	setopt(curl, CURLOPT_SSL_VERIFYPEER, 0)
	setopt(curl, CURLOPT_SSL_VERIFYHOST, 0)
	setopt(curl, CURLOPT_CONNECTTIMEOUT, 10)
	setopt(curl, CURLOPT_TIMEOUT, 20)
	if slist then setopt(curl, CURLOPT_HTTPHEADER, slist) end
	if DEBUG then setopt(curl, CURLOPT_VERBOSE, 1) end

	local res = libcurl.curl_easy_perform(curl)
	local http_code = 0
	if res == 0 then
		libcurl.curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, int32)
		http_code = int32[0]
	end

	if slist then libcurl.curl_slist_free_all(slist) end
	libcurl.curl_easy_cleanup(curl)

	if res ~= 0 then
		return nil, string.format("curl perform failed: code %d", res)
	end
	return http_code, DATA_BUFFER
end

-- HTTP GET, 下载到文件
-- mtls: 是否启用 mTLS 双向证书认证（固件下载需要，version-all 不需要）
local function http_download(url, headers, output_file, mtls)
	local fp = ffi.C.fopen(output_file, "wb")
	if fp == nil then
		return nil, "cannot open output file: " .. output_file
	end

	local curl = libcurl.curl_easy_init()
	if curl == nil then
		ffi.C.fclose(fp)
		return nil, "curl init failed"
	end

	local slist = headers and make_slist(headers) or nil

	setopt(curl, CURLOPT_URL, url)
	setopt(curl, CURLOPT_WRITEDATA, fp)
	setopt(curl, CURLOPT_FOLLOWLOCATION, 1)

	-- mTLS 双向证书认证
	if mtls then
		setopt(curl, CURLOPT_SSL_VERIFYPEER, 1)
		setopt(curl, CURLOPT_SSL_VERIFYHOST, 2)
		setopt(curl, CURLOPT_CAINFO,  SSL_CAINFO)
		setopt(curl, CURLOPT_SSLCERT, SSL_CERT)
		setopt(curl, CURLOPT_SSLKEY,  SSL_KEY)
	else
		setopt(curl, CURLOPT_SSL_VERIFYPEER, 0)
		setopt(curl, CURLOPT_SSL_VERIFYHOST, 0)
	end
	setopt(curl, CURLOPT_CONNECTTIMEOUT, 30)
	if slist then setopt(curl, CURLOPT_HTTPHEADER, slist) end
	if DEBUG then setopt(curl, CURLOPT_VERBOSE, 1) end

	-- 进度回调，输出到 stdout
	setopt(curl, CURLOPT_NOPROGRESS, 0)
	setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_cb_ptr)

	local res = libcurl.curl_easy_perform(curl)
	local http_code = 0
	if res == 0 then
		libcurl.curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, int32)
		http_code = int32[0]
	end

	if slist then libcurl.curl_slist_free_all(slist) end
	libcurl.curl_easy_cleanup(curl)
	ffi.C.fclose(fp)

	if res ~= 0 then
		return nil, string.format("curl perform failed: code %d", res)
	end
	if http_code ~= 200 then
		os.remove(output_file)
		return nil, string.format("HTTP error: %d", http_code)
	end
	return true
end

----------------------------------------------------------------
-- Crypto helpers
----------------------------------------------------------------

local function to_hex(buf, len)
	local t = {}
	for i = 1, len do
		t[i] = string.format("%02x", string.byte(buf, i))
	end
	return table.concat(t)
end

local function hmac_sha256_hex(key, data)
	local out_len = ffi.new("uint[1]")
	local out_buf = ffi.new("uchar[32]")
	local md = crypto.HMAC(crypto.EVP_sha256(),
		ffi.cast("const void *", key), #key,
		ffi.cast("const uchar *", data), #data,
		out_buf, out_len)
	if md == nil then
		return nil, "HMAC compute failed"
	end
	local n = tonumber(out_len[0])
	return to_hex(ffi.string(out_buf, n), n)
end

-- 收集非空参数，按 Key 字母升序排列后拼接，计算 HMAC-SHA256
local function calc_sign(params, secret)
	local keys = {}
	for k, v in pairs(params) do
		if v and v ~= "" then
			keys[#keys + 1] = k
		end
	end
	table.sort(keys)
	local parts = {}
	for _, k in ipairs(keys) do
		parts[#parts + 1] = k .. "=" .. params[k]
	end
	local raw = table.concat(parts, "&")
	dbg("sign string: %s", raw)
	local sign, err = hmac_sha256_hex(secret, raw)
	if not sign then
		return nil, "sign failed: " .. err
	end
	dbg("sign result: %s", sign)
	return sign
end

local function rand10()
	local t = {}
	for i = 1, 10 do
		t[i] = tostring(math.random(0, 9))
	end
	return table.concat(t)
end

----------------------------------------------------------------
-- Business logic
----------------------------------------------------------------

local function md5_file(path)
	local f = io.popen("md5sum " .. path)
	if not f then return nil, "md5sum failed" end
	local line = f:read("*l")
	f:close()
	return line and line:match("^(%x+)")
end

local function get_device_info()
	local ikrelease = load_config.load_release()
	local gwid = ikrelease.GWID
	local platform
	if ikrelease.MODELTYPE == "X86" or ikrelease.MODELTYPE == "X86ENT" then
		platform = (ikrelease.SYSBIT == "x64") and "x86-64" or "x86-32"
	else
		platform = ikrelease.ARCH
		ikrelease.ENTERPRISE = "enterprise"
	end
	local dev = {
		gwid      = gwid,
		platform  = platform,
		secret    = string.sub(gwid, -10),
		system    = ikrelease.ENTERPRISE and "enterprise" or "community",
		modelType = ikrelease.MODELTYPE or "",
	}
	dbg("device: gwid=%s platform=%s system=%s modelType=%s", dev.gwid, dev.platform, dev.system, dev.modelType)
	return dev
end

local function request_sign_url(dev, firmware_name, nonce, file_checksum)
	local sign, err = calc_sign({
		["X-Device-Platform"] = dev.platform,
		["X-Firmware-Name"]   = firmware_name,
		["X-Gw-Id"]           = dev.gwid,
		["X-Nonce"]           = nonce,
		["X-System-Version"]  = dev.system,
		["X-Model-Type"] = dev.modelType,
	}, dev.secret)
	if not sign then
		return nil, err
	end

	local headers = {
		["X-Device-Platform"] = dev.platform,
		["X-System-Version"]  = dev.system,
		["X-Gw-Id"]           = dev.gwid,
		["X-Firmware-Name"]   = firmware_name,
		["X-Sign"]            = sign,
		["X-Nonce"]           = nonce,
		["X-Model-Type"] = dev.modelType,
	}

	local code, body = http_post("https://devapi.ikuai8.com/firmware/sign-url", headers)
	if not code then
		return nil, "sign-url request failed: " .. body
	end
	dbg("sign-url response [%d]: %s", code, body)

	if code ~= 200 then
		return nil, string.format("sign-url HTTP error: %d, body: %s", code, body)
	end

	local ok, result = pcall(cjson.decode, body)
	if not ok then
		return nil, "sign-url JSON decode error: " .. tostring(result)
	end

	if result.code ~= 0 then
		return nil, string.format("sign-url API error: code=%s message=%s",
			tostring(result.code), tostring(result.message or ""))
	end

	if not result.data then
		return nil, "sign-url API response missing data"
	end

	return result.data
end

local function request_version_all(dev, nonce, file_checksum)
	local sign, err = calc_sign({
		["X-Device-Platform"] = dev.modelType,
		["X-Gw-Id"]           = dev.gwid,
		["X-Nonce"]           = nonce,
		-- X-Firmware-Name、X-System-Version、X-Model-Type 不参与签名
	}, dev.secret)
	if not sign then
		return nil, err
	end

	local headers = {
		["X-Device-Platform"] = dev.modelType,
		["X-Gw-Id"]           = dev.gwid,
		["X-Nonce"]           = nonce,
		["X-Sign"]            = sign,
	}

	local code, body = http_get("https://devapi.ikuai8.com/firmware/version-all", headers)
	if not code then
		return nil, "version-all request failed: " .. body
	end
	dbg("version-all response [%d]: %s", code, body)

	if code ~= 200 then
		return nil, string.format("version-all HTTP error: %d, body: %s", code, body)
	end

	local ok, result = pcall(cjson.decode, body)
	if not ok then
		return nil, "version-all JSON decode error: " .. tostring(result)
	end

	if result.code ~= 0 then
		return nil, string.format("version-all API error: code=%s message=%s",
			tostring(result.code), tostring(result.message or ""))
	end

	if not result.data then
		return nil, "version-all API response missing data"
	end

	return result.data
end

local function download_firmware(url, token, gwid, output_file)
	dbg("download url: %s", url)
	local headers = {
		["X-Auth-Token"] = token,
		["X-Gw-Id"]      = gwid,
	}
	return http_download(url, headers, output_file, true)
end

----------------------------------------------------------------
-- Main
----------------------------------------------------------------

local function main()
	math.randomseed(os.time())

	local mode = posargs[1]

	----------------------------------------------------------------
	-- version-all 模式：查询最新固件版本描述文件地址
	-- 用法: download.lua [-d] Version_all <output_file>
	-- 从 API 获取 fileUrl 后下载版本描述文件到 output_file
	----------------------------------------------------------------
	if mode == "Version_all" then
		local output_file = posargs[2]
		if not output_file then
			return 1, "Usage: download.lua [-d] Version_all <output_file>"
		end

		local dev   = get_device_info()
		local nonce = rand10()

		-- 文件已存在则计算 checksum 上传，供服务端判断是否需要重新下载；不存在则传空
		local file_checksum = ""
		local f = io.open(output_file, "r")
		if f then
			f:close()
			file_checksum = md5_file(output_file) or ""
			dbg("local file checksum: %s", file_checksum)
		end

		local data, err = request_version_all(dev, nonce, file_checksum)
		if not data then
			return 2, err -- 2: 请求失败
		end

		dbg("versionType=%s isBeta=%s md5=%s", tostring(data.versionType), tostring(data.isBeta), tostring(data.md5))

		-- 本地文件 MD5 与服务端一致，无需重新下载
		if file_checksum ~= "" and data.md5 and file_checksum == data.md5 then
			dbg("already up to date (md5 match)")
			return 0
		end

		-- 从 API 返回结果中获取 fileUrl 并下载文件
		if not data.fileUrl or data.fileUrl == "" then
			return 3, "API response missing fileUrl"
		end

		dbg("downloading version-all from: %s", data.fileUrl)

		-- 使用 http_download 下载文件（OSS 直链，不需要额外 headers）
		local ok, err = http_download(data.fileUrl, nil, output_file)
		if not ok then
			return 4, "download version-all failed: " .. err
		end

		return 0
	end

	----------------------------------------------------------------
	-- download 模式（默认）：下载固件文件，调用方式不变
	-- 用法: download.lua [-d] <firmware_name> <output_file>
	----------------------------------------------------------------
	local firmware_name = posargs[1]
	local output_file   = posargs[2]

	if not firmware_name or not output_file then
		return 1, "Usage: download.lua [-d] <firmware_name> <output_file>" -- 1: 参数错误
	end

	local dev   = get_device_info()
	local nonce = rand10()

	-- 文件已存在则计算 checksum 上传，供服务端判断是否需要重新下载；不存在则传空
	local file_checksum = ""
	local f = io.open(output_file, "r")
	if f then
		f:close()
		file_checksum = md5_file(output_file) or ""
		dbg("local file checksum: %s", file_checksum)
	end

	-- Step 1: 请求签名下载URL
	local data, err = request_sign_url(dev, firmware_name, nonce, file_checksum)
	if not data then
		return 2, err -- 2: 签名/API请求失败
	end

	-- 服务端校验 MD5 一致，本地文件已是最新，无需下载
	if data.md5Verified and data.md5Match then
		dbg("already up to date (md5 match, ossMD5=%s)", tostring(data.ossMD5))
		return 0 -- 0: 已是最新
	end

	if not data.signUrl or data.signUrl == "" then
		return 2, "sign-url API response missing signUrl"
	end

	-- Step 2: 下载固件文件
	local ok, err = download_firmware(data.signUrl, data.token, dev.gwid, output_file)
	if not ok then
		return 3, err -- 3: 固件下载失败
	end

	return 0 -- 0: 成功
end

local code, err = main()
if code ~= 0 then
	io.stderr:write(tostring(err) .. "\n")
end
os.exit(code)
