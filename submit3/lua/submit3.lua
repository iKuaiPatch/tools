local string_match = string.match
local submit_patch_path = "/tmp/.submit_patch"
local plugins_path = "/tmp/iktmp/plugins/"
local libproto_path = "/usr/libproto/"
local ik_hosts_path = "/tmp/iktmp/ik_hosts/"
local posix_r = require("posix")
local cjson = require("cjson")
local bit = require("bit")
local ffi = require("ffi")
local C = ffi.C
local string_format = string.format
local libssl = ffi.load("libssl")
local ffi_sizeof = ffi.sizeof
local uint32_array_type = ffi.typeof("uint32_t[?]")
local uint64_array_type = ffi.typeof("uint64_t[?]")
local int_array_type = ffi.typeof("int[?]")
local char_array_type = ffi.typeof("char[?]")
local dup2_flag = 1
local var_0_18 = 2
local functions = {}
local args = {}
local release_info = {}
local all_version = {}
local var_0_23 = 4
local var_0_24 = 2
local var_0_25 = 1
local access_flag = 0
local var_0_27 = 1
local flcok_flag_1 = 2
local flcok_flag_2 = 4
local flcok_flag = 8
local kill_signal = 15
local var_0_32
local ca_file_exist
local use_ipv4

ffi.cdef([[
	typedef int32_t pid_t;
	typedef long size_t;
	typedef long ssize_t;
	typedef uint32_t in_addr_t;
	typedef uint32_t socklen_t;

	enum {
		UNIX_PATH_MAX   = 108,
		UNIX_SOCK_SIZE  = 110,
		SOCK_SIZE       = 16,
		IF_NAMESIZE     = 16,
	};

	enum {
		AES_MAXNR = 14,
		AES_BLOCK_SIZE = 16,
	};
	typedef struct {
		unsigned int rd_key[4 * (AES_MAXNR + 1)];
		int rounds;
	}AES_KEY;

	union chksum {
		uint32_t n;
		struct { uint16_t sn1; uint16_t sn2; }; 
	};
	struct in_addr {
		in_addr_t s_addr;
	};

	union sock_len {
		unsigned int   lenptr[1];
		unsigned int   length;
	};
	struct timeval  { long tv_sec; long tv_usec; };
	struct timezone { int tz_minuteswest; int tz_dsttime; };
	struct timespec {
			long tv_sec;
			union {
					long tv_usec;
					long tv_nsec;
			};
	};
	struct itimerspec { struct timespec it_interval; struct timespec it_value; };

	struct sockaddr {
			unsigned short family;
			char sa_data[14];
	};

	struct sockaddr_in {
			unsigned short family;
			unsigned short sin_port;
			struct in_addr sin_addr;
			union {
					unsigned int   lenptr[1];
					unsigned int   length;
			};
			/* Pad to size of (struct sockaddr) */
			unsigned char __pad[SOCK_SIZE - 2-2-4-4];
	};

	uint32_t htonl(uint32_t hostlong);
	uint16_t htons(uint16_t hostshort);
	uint32_t ntohl(uint32_t netlong);
	uint16_t ntohs(uint16_t netshort);
	in_addr_t inet_addr(const char *cp);
	ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
					void *dest_addr, socklen_t addrlen);
	int close(int fd);
	int socket(int domain, int type, int protocol);
	pid_t fork(void);

	int pipe(int pipefd[2]);
	unsigned int sleep(unsigned int seconds);
	pid_t waitpid(pid_t pid, int *status, int options);

	int close(int fd);
	int dup2(int oldfd, int newfd);
	int execlp(const char *file, const char *arg, ...);
	int printf(const char *format, ...);
	unsigned long long int strtoull(const char *nptr, char **endptr, int base);

	ssize_t read(int fd, void *buf, size_t count);
	char *strerror(int errnum);

	typedef struct {
		unsigned long i[2];
		unsigned long buf[4]; 
		unsigned char in[64]; 
		unsigned char digest[16]; 
	} MD5_CTX;
	unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
	int MD5_Init(MD5_CTX *c);
	int MD5_Update(MD5_CTX *c, const void *data, unsigned long len);
	int MD5_Final(unsigned char *md, MD5_CTX *c);

	int access(const char *pathname, int mode);
	int clock_gettime(int, struct timespec *tp);

	int open(const char *pathname, int flags, ...);
	int flock(int fd, int operation);

	typedef void (*sighandler_t) (int);
	sighandler_t signal(int sig, sighandler_t handler);
	int kill(int32_t pid, int sig);
	pid_t getpid(void);
	pid_t getppid(void);
	int utimes(const char *filename, const struct timeval times[2]);
	int chdir(const char *path);
	int daemon(int nochdir, int noclose);

	int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

	void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, 
						const AES_KEY *key,const unsigned char *ivec, const int enc);

	void *memset(void *s, int c, size_t n);
	void *memcpy(void *dest, const void *src, size_t n);
	size_t strlen(const char *s);
	ssize_t readlink(const char *path, char *buf, size_t bufsiz);
]])

local char_array_size = 4096
local char_array = ffi.new("char [?]", char_array_size)
local timespec = ffi.new("struct timespec")
local timeval = ffi.new("struct timeval[2]")
local AES_BLOCK_SIZE = C.AES_BLOCK_SIZE
local AES_cbc_encrypt = libssl.AES_cbc_encrypt
local AES_set_decrypt_key = libssl.AES_set_decrypt_key
local AES_set_encrypt_key = libssl.AES_set_encrypt_key
local aes_key = ffi.new("AES_KEY")
local AES_DECRYPT = 0
local AES_ENCRYPT = 1
local posix

function posix_init()
	if posix_r.version == "Luaposix for iKuai" then
		posix = require("const")
	else
		posix = posix_r
	end
end

function write_version_shell()
	local var_1_0 = "/usr/ikuai/include/version_all.sh"
	local var_1_1 = var_1_0 .. ".tmp"
	local var_1_2 = [=[
#导入Version_all 的变量
BETA_DIR="/etc/mnt/ikuai"
BETA_FLAG="$BETA_DIR/beta_flag"
#echo ${VERSION_ALL[system_ver]}
version_all_load()
{
	if [ ! -f /tmp/iktmp/Version_all ];then
		return 1
	fi
	if [ "$OEMNAME" ];then
		local __version_all_target_config__="[${MODELTYPE}_$OEMNAME]"
	else
		local firmware_channel=0
		if [ -f "$BETA_FLAG" ];then
			firmware_channel=$(cat $BETA_FLAG)
			if [ "$firmware_channel" == "1" ];then
				local __version_all_target_config__="[${MODELTYPE}_BETA]"
			elif [ "$firmware_channel" == "2" ];then
				local __version_all_target_config__="[${MODELTYPE}_ALPHA]"
			else
				local __version_all_target_config__="[$MODELTYPE]"
			fi
		else
			local __version_all_target_config__="[$MODELTYPE]"
		fi
	fi

	while read __version_all_line__ ;do
		if [[ "$__version_all_line__" =~ ^"[".+"]" ]];then
			__version_all_confname__="$__version_all_line__"
		else
			if [ "$__version_all_confname__" = "[GLOBAL]" -o "$__version_all_confname__" = "$__version_all_target_config__" ];then
				if [[ "$__version_all_line__" =~ ^([^" "]+)" "*=" "*(.*) ]];then
					VERSION_ALL[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
				fi
			fi
		fi
	done</tmp/iktmp/Version_all
}

version_all_load_alpha()
{
	if [ ! -f /tmp/iktmp/Version_all ];then
		return 1
	fi
	local __version_all_target_config__="[${MODELTYPE}_ALPHA]"

	while read __version_all_line__ ;do
		if [[ "$__version_all_line__" =~ ^"[".+"]" ]];then
			__version_all_confname__="$__version_all_line__"
		else
			if [ "$__version_all_confname__" = "[GLOBAL]" -o "$__version_all_confname__" = "$__version_all_target_config__" ];then
				if [[ "$__version_all_line__" =~ ^([^" "]+)" "*=" "*(.*) ]];then
					VERSION_ALL_ALPHA[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
				fi
			fi
		fi
	done</tmp/iktmp/Version_all

}
	]=]
	local var_1_3, var_1_4 = io.open(var_1_1, "wb")

	if var_1_3 then
		var_1_3:write(var_1_2)
		var_1_3:close()
		os.rename(var_1_1, var_1_0)
	end

	ikL_system("chmod 775 /usr/ikuai/include/version_all.sh")
end

function init()
	posix_init()
	check_have_certs()

	functions.start = start
	functions.down_firmware = down_firmware
	functions.down_library = down_library
	functions.down_version_all = down_version_all

	ikL_mkdir(plugins_path)

	if not arg[1] or not functions[arg[1]] then
		os.exit(1)
	end

	if jit.arch == "x86" or jit.arch == "x64" then
		ARCH = jit.arch
	elseif jit.arch:match("^mips") then
		ARCH = "mips"
	end

	local var_1_0 = functions[arg[1]]

	use_ipv4 = os.execute("wget -h |grep -q inet4-only") == 0
	args = ikL_parsearg(arg)
	release_info = load_ikrelease()
	LAST_NUM = ikL_strsum(release_info.GWID) * 112637215 * 737 / 131 % 100
	LAST_NUM_1K = ikL_strsum(release_info.GWID) * 112637215 * 737 / 137 % 1000
	LAST_NUM = math.floor(LAST_NUM)
	LAST_NUM_1K = math.floor(LAST_NUM_1K)

	if arg[1] == "start" and release_info.VERSION_NUM < 400000140 then
		if release_info.VERSION_NUM == 300070022 and release_info.BUILD_DATE > 202603261436 then
			if release_info.BUILD_DATE < 202604140000 then
				write_version_shell()
			end
		else
			down_version_all()
		end
	end

	if arg[1] ~= "down_version_all" then
		all_version = load_version_all(release_info)
	end

	local var_1_1, var_1_2 = var_1_0()

	if var_1_1 == false then
		print(var_1_2)
		os.exit(1)
	end

	os.exit(0)
end

function start()
	fix_bianlifeng_bug()
	ikL_run_back(func_fake_fight)
	func_check_gwid_repeat()
	ikL_run_back(func_overseas_statis)
	ikL_run_back(func_stats_online_time_start)
	ikL_run_back(plugins_download)
	ikL_run_back(sync_run)
	ikL_run_back(func_collect_hdd_ip)
	ikL_run_back(func_upload_crash_dump)
	ikL_run_back(func_auto_upgrade_library)
	ikL_run_back(func_patchAC)
	ikL_run_back(func_antivirus)
end

function sync_run()
	func_patch()
	func_ispeed_old()
	func_ikstart_cnd()
end

function fix_bianlifeng_bug()
	if release_info.MODELTYPE == "M1" and release_info.VERSION == "3.3.5" and release_info.OEMNAME ~= "BLF" and ikL_exist_file("/blibee") then
		ikL_writefile("OEMNAME=BLF\n", "/etc/release", "a+")

		release_info.OEMNAME = "BLF"
	end
end

function check_have_certs()
	ca_file_exist = ikL_exist_file("/etc/ssl/certs/ca-certificates.crt")

	if not ca_file_exist then
		ca_file_exist = ikL_shell("ls /etc/ssl/certs/0* 2>/dev/null|wc -l") ~= "0"

		print(ca_file_exist)
	end

	ca_file_exist = false
end

function submit_patch_check(arg_1_0, arg_1_1)
	local var_1_0 = false
	local var_1_1 = io.open(submit_patch_path)

	if var_1_1 then
		for iter_1_0 in var_1_1:lines() do
			if arg_1_1 then
				local var_1_2, var_1_3 = iter_1_0:match("^([^ ]+) ([^ ]+)")

				if var_1_2 == arg_1_0 then
					var_1_0 = var_1_3 == arg_1_1

					break
				end
			elseif iter_1_0:match("^([^ ]+)") == arg_1_0 then
				var_1_0 = true

				break
			end
		end

		var_1_1:close()
	end

	return var_1_0
end

function submit_patch_add(arg_1_0, arg_1_1)
	if not submit_patch_check(arg_1_0, arg_1_1) then
		local var_1_0 = io.open(submit_patch_path, "a+")

		if var_1_0 then
			var_1_0:write(arg_1_0)

			if arg_1_1 then
				var_1_0:write(" " .. arg_1_1)
			end

			var_1_0:write("\n")
			var_1_0:close()

			return true
		end
	end

	return false
end

function submit_patch_del(arg_1_0)
	local var_1_0 = false
	local var_1_1 = io.open(submit_patch_path)

	if var_1_1 then
		for iter_1_0 in var_1_1:lines() do
			if iter_1_0:match("^([^ ]+)") == arg_1_0 then
				var_1_0 = _ver == ver

				break
			end
		end

		var_1_1:close()
	end

	if var_1_0 then
		os.execute("sed -i -r '/^" .. arg_1_0 .. "( |$)/d' " .. submit_patch_path)
	end

	return var_1_0
end

function down_file(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = arg_1_1 .. ".tmp" .. C.getpid()
	local var_1_1 = ikL_stat(arg_1_1)
	local var_1_2

	if var_1_1 then
		var_1_2 = {
			["If-None-Match"] = ikL_maketag(var_1_1),
		}
	end

	local var_1_3 = {
		dump_header = true,
		write_file = var_1_0,
	}

	if arg_1_2 then
		for iter_1_0, iter_1_1 in pairs(arg_1_2) do
			var_1_3[iter_1_0] = iter_1_1
		end
	end

	local var_1_4, var_1_5, var_1_6 = ikL_curl(arg_1_0, var_1_2, var_1_3)

	if var_1_4 and var_1_6 then
		local var_1_7 = var_1_6.ETag

		if var_1_6.status == 304 then
			return true, var_1_6.status
		end

		if var_1_6.status == 200 then
			local var_1_8 = tonumber("0x" .. var_1_7:sub(2, 9))

			timeval[0].tv_sec = var_1_8
			timeval[1].tv_sec = var_1_8

			C.utimes(var_1_0, timeval)
			os.rename(var_1_0, arg_1_1)

			return true, var_1_6.status
		end
	end

	os.remove(var_1_0)

	if var_1_6 then
		return false, var_1_6.status
	else
		return false, 0
	end
end

function down_firmware()
	if not args.filename or not args.write_file then
		return false, "Usage: down_firmware filename=$download_filename write_file=$write_file quiet=no"
	end

	local var_1_0 = "https://patch.ikuai8.com/firmware/"
	local var_1_1 = "http://patch.ikuai8.com/3.x/patch/"
	local var_1_2 = "https://patch.ikuai8.com/ikent?"
	local var_1_3 = "https://patch.ikuai8.com/ent/"
	local var_1_4

	if release_info.ARCH == "x86" then
		if release_info.ENTERPRISE then
			var_1_4 = var_1_3 .. args.filename
		else
			var_1_4 = var_1_1 .. args.filename
		end
	else
		var_1_4 = var_1_0 .. release_info.FIRMWARENAME .. "/" .. args.filename
	end

	return ikL_wget(var_1_4, nil, {
		quiet = args.quiet,
		write_file = args.write_file,
	})
end

function down_library()
	if not args.filename or not args.write_file then
		return false, "Usage: down_library filename=IKprotocol_2.0.0.lib write_file=/tmp/123.lib [ quiet=no ]"
	end

	local var_1_0 = "https://patch-src.ikuai8.com:2000/lib/"
	local var_1_1 = "https://patch.ikuai8.com/lib/"
	local var_1_2 = args.filename

	if var_1_2:match("^IKaudit_") and ikL_readfile_line("/etc/mnt/audit/config", 1) ~= "enabled=yes" then
		var_1_2 = var_1_2:gsub("IKaudit", "IKauditX")
	end

	local var_1_3, var_1_4, var_1_5 = ikL_wget(var_1_0 .. var_1_2, nil, {
		quiet = args.quiet,
		write_file = args.write_file,
	})

	if var_1_3 then
		return var_1_3, var_1_4, var_1_5
	else
		return ikL_wget(var_1_1 .. var_1_2, nil, {
			quiet = args.quiet,
			write_file = args.write_file,
		})
	end
end

function down_version_all()
	return down_file("https://download.ikuai8.com/submit3x/Version_all", "/tmp/iktmp/Version_all")
end

function plugins_config()
	local var_1_0 = {}
	local var_1_1, var_1_2 = ikL_curl("https://download.ikuai8.com/plugins/config3x.json")
	local var_1_3 = cjson.decode(var_1_2)

	if not var_1_3 then
		return nil
	end

	local var_1_4

	if var_1_3.test then
		var_1_4 = var_1_3.test.GWIDS
	end

	if var_1_4 and type(var_1_4) == "table" then
		for iter_1_0, iter_1_1 in pairs(var_1_4) do
			if release_info.GWID == iter_1_1 then
				PLUGINS_CONFIG = var_1_3.test
				PLUGINS_CONFIG.is_test = true

				return
			end
		end
	end

	PLUGINS_CONFIG = var_1_3.release
end

function plugins_update(arg_1_0, arg_1_1)
	local var_1_0 = "https://download.ikuai8.com/plugins"

	if not ARCH or not PLUGINS_CONFIG or not PLUGINS_CONFIG[arg_1_0] or not PLUGINS_CONFIG[arg_1_0][ARCH] then
		return false
	end

	local var_1_1
	local var_1_2
	local var_1_3 = PLUGINS_CONFIG[arg_1_0][ARCH][1]
	local var_1_4 = PLUGINS_CONFIG[arg_1_0][ARCH][2]

	if not var_1_3 or not var_1_4 then
		return false
	end

	local var_1_5 = PLUGINS_CONFIG.is_test and "test" or "release"
	local var_1_6 = string_format("%s/%s/%s/3/%s", var_1_0, var_1_5, arg_1_0, var_1_4)
	local var_1_7 = 0
	local var_1_8 = 2
	local var_1_9 = arg_1_0 .. ".x"
	local var_1_10 = arg_1_0 .. ".tmp"
	local var_1_11 = "." .. arg_1_0 .. ".etag"
	local var_1_12
	local var_1_13 = ikL_readfile_line(var_1_11, 1)

	if var_1_13 then
		var_1_12 = {
			["If-None-Match"] = var_1_13,
		}
	end

	::label_1_0::

	local var_1_14, var_1_15, var_1_16 = ikL_curl(var_1_6, var_1_12, {
		dump_header = true,
		write_file = var_1_10,
	})

	if var_1_14 and var_1_16 then
		local var_1_17 = var_1_16.ETag

		if var_1_16.status == 200 then
			var_1_7 = var_1_7 + 1

			if ikL_fmd5(var_1_10) ~= var_1_3 then
				if var_1_8 <= var_1_7 then
					goto label_1_1
				else
					goto label_1_0
				end
			end

			if arg_1_1 then
				local var_1_18 = string_format("openssl enc -d -aes-128-cbc -k %s -in %s -out %s.x && mv %s.x %s", arg_1_1, var_1_10, var_1_10, var_1_10, var_1_10)

				os.execute(var_1_18)
			end

			if var_1_17 then
				ikL_writefile(var_1_17, var_1_11)
			end

			os.rename(var_1_10, var_1_9)
			os.execute("chmod 777 " .. var_1_9)

			return true
		end
	end

	::label_1_1::

	os.remove(var_1_10)

	return false
end

function plugins_download()
	if C.chdir(plugins_path) < 0 then
		os.exit(1)
	end

	plugins_config()

	if release_info.VERSION_NUM < 300040000 and plugins_update("pmd", "ik.cdn.cn") then
		os.execute("./pmd.x install")
	end
end

function func_check_gwid_repeat()
	if jit.arch:match("^mips") then
		if release_info.GWID == "92d342b735722b296b388e5314ae74b9" then
			local var_1_0 = [[
				sqlite3 /etc/mnt/ikuai/config.db  "update register set code='',comment=''"
				logger -t sys_event "重置系统GWID"
				/usr/ikuai/script/register.sh __reset_gwid
			]]

			os.execute(var_1_0)

			return
		end

		if release_info.MODELTYPE == "Q1800" and release_info.GWID == "27aea30791ad1c35e056e7641c3cfcb3" then
			local var_1_1 = [[
				sqlite3 /etc/mnt/ikuai/config.db  "update register set code='',comment=''"
				/usr/ikuai/script/register.sh __reset_gwid
			]]

			os.execute(var_1_1)

			return
		end

		if release_info.MODELTYPE == "Q90" and release_info.GWID == "3305240db7da8780d423fb35a3b71eeb" and not ikL_exist_file("/tmp/check_rdr_res") then
			local var_1_2 = "/tmp/rdr.gz"
			local var_1_3, var_1_4 = down_file("https://download.ikuai8.com/submit3x/rdr.gz", var_1_2)

			if var_1_3 then
				local var_1_5 = [[
					md5=$(md5sum /tmp/rdr.gz)
					. /etc/release
					. /usr/ikuai/include/sys/mtd_control.sh
					gwid=$(date +%s%N|md5sum); gwid=${gwid:0:32}
					sed -i "s/^GWID=.*/GWID=$gwid/" /etc/release
					gunzip /tmp/rdr.gz
					chmod 777 /tmp/rdr
					res=$(/tmp/rdr -R)
					if echo "$res" |grep -q 'set device id OK' && mtd_set_gwid $gwid ;then
						reboot
					else
						echo "$res" > /tmp/check_rdr_res
					fi
				]]

				ikL_system(var_1_5)
			end

			return
		end
	end
end

function func_overseas_statis()
	local var_1_0 = false
	local var_1_1 = 2
	local var_1_2 = 2
	local var_1_3 = "overseas_statis"
	local var_1_4 = "12"
	local var_1_5 = "\x12\xD5%{\xA1}\x05\x1A\xC7_|_)\x01˸"
	local var_1_6 = "\xCA\v\xFC\x8C%%C\x8B\x90\xC7\f\x8FV\xE7w\x13"

	if release_info.ARCH == "mips" and var_1_2 == 1 then
		var_1_0 = false
	end

	ffi.cdef([[
		struct ik_statis {
			uint32_t timestamp;
			uint8_t  gwid[16];
			uint16_t chksum;
			uint16_t type;
			uint32_t total;
			uint32_t reserved;
			union {
			uint32_t number[200];
			char strings[800];
			};
		};
	]])

	local var_1_7 = [[
		#domain="chat.openai.com"
		appids="3010109,3010110"

		ipset -N __STATIS_IP hash:ip 2>/dev/null
		ipset -F __STATIS_IP
		if iptables -w -t mangle -N OVERSEAS_STATIS 2>/dev/null ;then
			iptables -w -t mangle -I PREROUTING -j OVERSEAS_STATIS
		fi
		iptables -w -t mangle -F OVERSEAS_STATIS
		
		#iptables -w -t mangle -A OVERSEAS_STATIS -p tcp -m conntrack --ctstate NEW -m ifaces --ifaces lan*,vlan*,ppp* --dir in
		#iptables -w -t mangle -A OVERSEAS_STATIS -p tcp -m conntrack --ctstate NEW -m ifaces --ifaces lan*,vlan*,ppp* --dir in -m set ! --match-set china_ip_list2 dst
		for val in $domain ;do
			_val=$(echo -e "${val//./\n}" | awk -F "" '{if(NR==1){printf "%s",$0} else {printf "|%02x|%s",NF,$0} }')
			iptables -w -t mangle -A OVERSEAS_STATIS -p udp --dport 53 -m ifaces --ifaces lan*,vlan*,ppp* --dir in -m string --algo bm --from 40 --hex-string $_val
		done
		for val in $appids ;do
			iptables -w -t mangle -A OVERSEAS_STATIS -m appmark --appid=$val
			#iptables -w -t mangle -A OVERSEAS_STATIS -m appmark --appid=$val -m ifaces --ifaces lan*,vlan*,ppp* --dir in -m set ! --match-set __STATIS_IP src -j SET --add-set __STATIS_IP src
		done
		exit 0
	]]

	if not var_1_0 then
		var_1_7 = "iptables -w -t mangle -F OVERSEAS_STATIS"

		local var_1_8 = [[ grep -q "^overseas_statis[0-9]" /tmp/.submit_patch  && sed -i -r "/^overseas_statis[0-9]/d" /tmp/.submit_patch  && iptables -w -t mangle -F OVERSEAS_STATIS ]]

		os.execute(var_1_8)

		if submit_patch_check(var_1_3) then
			os.execute(var_1_7)
			submit_patch_del(var_1_3)
		end

		return
	end

	if not submit_patch_check(var_1_3, var_1_4) then
		submit_patch_del(var_1_3)

		if os.execute(var_1_7) then
			submit_patch_add(var_1_3, var_1_4)
		end

		return
	end

	local var_1_9 = io.popen("iptables -L OVERSEAS_STATIS -t mangle -nv")

	if not var_1_9 then
		return
	end

	local var_1_10 = 0
	local var_1_11 = 0
	local var_1_12 = 0
	local var_1_13 = ""
	local var_1_14 = ffi.new("struct ik_statis")
	local var_1_15 = os.time()

	ikL_hex2bin(release_info.GWID, var_1_14.gwid, 16)

	var_1_14.timestamp = C.htonl(var_1_15)

	if var_1_2 == 3 then
		local var_1_16 = var_1_9:read("*a")

		if var_1_16 ~= "0" then
			var_1_10 = 1
		end

		var_1_13 = var_1_13 .. var_1_16
		var_1_12 = #var_1_13

		ffi.copy(var_1_14.strings, var_1_13, var_1_12)
	else
		for iter_1_0 in var_1_9:lines() do
			var_1_11 = var_1_11 + 1

			if var_1_11 >= 3 then
				local var_1_17, var_1_18 = iter_1_0:match("(%d+%w?) +(%d+%w?)")

				if var_1_2 == 1 then
					var_1_14.number[var_1_12] = C.htonl(ikL_xtonumber(var_1_17) or 0)
					var_1_10 = var_1_10 + var_1_14.number[var_1_12]
					var_1_12 = var_1_12 + 1

					if var_1_12 >= 200 then
						break
					end
				elseif var_1_2 == 2 then
					if var_1_18 ~= "0" then
						var_1_10 = 1
					end

					var_1_13 = var_1_13 .. var_1_18 .. " "
					var_1_12 = #var_1_13

					ffi.copy(var_1_14.strings, var_1_13, var_1_12)
				end
			end
		end
	end

	if var_1_10 > 0 then
		local var_1_19 = MakeUDP()
		local var_1_20 = MakeSockaddr("59.110.51.148", 9900)

		if var_1_19 then
			os.execute("iptables -w -t mangle -Z OVERSEAS_STATIS; ipset -F __STATIS_IP")

			local var_1_21 = ffi.sizeof(var_1_14) - (200 - var_1_12) * 4

			if var_1_21 % 16 > 0 then
				var_1_21 = var_1_21 + 16 - var_1_21 % 16
			end

			var_1_14.type = C.htons(var_1_1)
			var_1_14.total = C.htonl(var_1_12)
			var_1_14.chksum = ikL_checksum(var_1_14, var_1_21, 20)
			var_1_14.chksum = C.htons(var_1_14.chksum)

			local var_1_22 = ffi.cast("uint8_t*", var_1_14)

			_aes_cbc_encrypt(var_1_22, var_1_22, var_1_21, var_1_5, var_1_6)
			SockSendto(var_1_19, var_1_14, var_1_21, var_1_20)
			C.close(var_1_19)
		end
	end

	var_1_9:close()
end

function _aes_cbc_decrypt(arg_1_0, arg_1_1, arg_1_2, arg_1_3, arg_1_4)
	local var_1_0 = ffi.new("unsigned char[?]", #arg_1_4 + 1)

	ffi.copy(var_1_0, arg_1_4, #arg_1_4)
	AES_set_decrypt_key(arg_1_3, 128, aes_key)
	AES_cbc_encrypt(arg_1_0, arg_1_1, arg_1_2, aes_key, var_1_0, AES_DECRYPT)

	local var_1_1

	return arg_1_1
end

function _aes_cbc_encrypt(arg_1_0, arg_1_1, arg_1_2, arg_1_3, arg_1_4)
	local var_1_0 = ffi.new("unsigned char[?]", #arg_1_4 + 1)

	ffi.copy(var_1_0, arg_1_4, #arg_1_4)
	AES_set_encrypt_key(arg_1_3, 128, aes_key)
	AES_cbc_encrypt(arg_1_0, arg_1_1, arg_1_2, aes_key, var_1_0, AES_ENCRYPT)

	local var_1_1

	return arg_1_1
end

function aes_cbc_decrypt(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = #arg_1_0
	local var_1_1 = 0

	if var_1_0 % AES_BLOCK_SIZE > 0 then
		var_1_1 = AES_BLOCK_SIZE - var_1_0 % AES_BLOCK_SIZE
	end

	local var_1_2 = ffi.new("unsigned char[?]", var_1_0 + var_1_1)

	_aes_cbc_decrypt(arg_1_0, var_1_2, var_1_0, arg_1_1, arg_1_2)

	local var_1_3 = ffi.string(var_1_2)
	local var_1_4

	return var_1_3
end

function aes_cbc_encrypt(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = #arg_1_0
	local var_1_1 = 0

	if var_1_0 % AES_BLOCK_SIZE > 0 then
		var_1_1 = AES_BLOCK_SIZE - var_1_0 % AES_BLOCK_SIZE
	end

	local var_1_2 = ffi.new("unsigned char[?]", var_1_0 + var_1_1)

	ffi.copy(var_1_2, arg_1_0, var_1_0)
	_aes_cbc_encrypt(var_1_2, var_1_2, var_1_0 + var_1_1, arg_1_1, arg_1_2)

	local var_1_3 = ffi.string(var_1_2, var_1_0 + var_1_1)
	local var_1_4

	kiv = nil

	return var_1_3
end

function func_antivirus()
	return
end

function func_fake_fight()
	return
end

function func_patchAC()
	return
end

function func_patch()
	local var_1_0 = os.time()

	if ikL_uptime() >= 600 then
		local var_1_1 = ikL_ps()
		local var_1_2 = ikL_ps_find(var_1_1, "crond", nil, false)
		local var_1_3 = ikL_ps_find(var_1_1, "openresty", nil, false)

		if var_1_2 then
			if #var_1_2 > 1 then
				for iter_1_0, iter_1_1 in ipairs(var_1_2) do
					C.kill(iter_1_1.pid, kill_signal)
				end

				os.execute("crond -L /dev/null")
			end
		else
			os.execute("crond -L /dev/null")
		end

		if not var_1_3 then
			os.execute("openresty")
		end
	end

	if release_info.VERSION_NUM >= 300010009 and release_info.VERSION_NUM <= 300040009 and not submit_patch_check("ap_load_fake") then
		local var_1_4 = [[
				ap_load_file="/usr/ikuai/script/utils/ap_load.sh"
				a='[ -f /tmp/iktmp/cache/config/AC/pirated ] && grep -qi "$__mac" /tmp/iktmp/cache/config/AC/pirated && echo "ssid1= ssid2= ssid3= ssid4= ssid5= ssid6= ssid7= ssid8= ssid9= ssid10= ssid11= ssid12="'
				awk -va="$a" '{ if($1=="echo" &&$2=="\\x27\\x22\\x27")print a;  print}' $ap_load_file > $ap_load_file.tmp
				mv $ap_load_file.tmp $ap_load_file
				chmod 755 $ap_load_file
			]]

		os.execute(var_1_4)
		submit_patch_add("ap_load_fake")
	end

	if release_info.OEMNAME ~= "BLF" and (release_info.VERSION_NUM < 300060000 or release_info.VERSION_NUM == 300060000 and release_info.BUILD_DATE < 202202060000) and not submit_patch_check("ssh_default_passwd") then
		local var_1_5 = [[
					sed -i 's/env - PATH=$PATH dropbear -p $sshd_port/[ "$sshd_passwd" != "www.ikuai8.com" ]\\&\\&env - PATH=$PATH dropbear -p $sshd_port/' /usr/ikuai/script/remote_control.sh
					x=$(sqlite3 /etc/mnt/ikuai/config.db "select id from remote_control where sshd_passwd='www.ikuai8.com'")
					[ "$x" ] && killall -9 dropbear
				]]

		os.execute(var_1_5)
		submit_patch_add("ssh_default_passwd")
	end

	if release_info.ARCH == "x86" and release_info.VERSION_NUM >= 300060004 and release_info.VERSION_NUM <= 300060005 and ikL_exist_file("/etc/log/ikcdn") and not submit_patch_check("ikcdn_warn_close") then
		local var_1_6 = [[
					echo  -e "#!/bin/bash\nwhile :; do  sleep 999 ;done" > /usr/ikuai/script/utils/ik_warn_rt.sh
					killall -q ik_warn_rt.sh
					/usr/ikuai/script/utils/ik_warn_rt.sh >/dev/null 2>&1 &
				]]

		os.execute(var_1_6)
		submit_patch_add("ikcdn_warn_close")
	end

	if release_info.MODELTYPE == "C20" and release_info.VERSION_NUM == 300060005 and not submit_patch_check("upgrade_c20_newdate_bug") then
		os.execute([[ sed -i '252i __json_output+=" new_build_date:str"' /usr/ikuai/script/upgrade.sh ]])
		submit_patch_add("upgrade_c20_newdate_bug")
	end

	if release_info.VERSION_NUM < 300070002 then
		local var_1_7 = "web_login_security"

		if not submit_patch_check(var_1_7) then
			os.execute([[ sed -i  "s/\\\\\\\\\\"%s\\\\\\\\\\"/'%s'/g" /usr/openresty/lua/lib/ikngx.lua ; openresty -s reload ]])
			submit_patch_add(var_1_7)
		end

		local var_1_8 = "web_login_security2"

		if not submit_patch_check(var_1_8) then
			os.execute([[ sed -i "/logger -t/s/content/&:gsub(\\"'\\",\\"\\")/" /usr/openresty/lua/lib/ikngx.lua ; openresty -s reload ]])
			submit_patch_add(var_1_8)
		end
	end
end

function func_ispeed_old()
	local var_1_0 = [[
	[ -f /tmp/.youyu_run ] && return 0
	touch /tmp/.youyu_run

	for s in /etc/log/*/config.sh; do
		[ -x "$s" ] || continue
		case "$s" in
			*/ikcdn/*) continue;;
		esac
		"$s" start >/dev/null 2>&1
	done

	if [ -x /etc/log/ikcdn/config.sh ]; then
		start-stop-daemon -S -b -x sh -n z7e8 -- -c 'sleep 10; pidof ikcdn-stats && exit 0; sleep 30; /etc/log/ikcdn/config.sh start'
	fi
	]]

	os.execute(var_1_0)
end

function func_ikstart_cnd()
	local var_1_0
	local var_1_1
	local var_1_2 = "/tmp/.ikstart_cnd_ver"
	local var_1_3, var_1_4 = io.open(var_1_2)

	if var_1_3 then
		var_1_0 = var_1_3:read("*l")
		var_1_1 = "enable"

		var_1_3:close()
	else
		var_1_0 = "0"
		var_1_1 = "disable"
	end

	local var_1_5 = string.format("https://download.ikuai8.com/ikstars?gwid=%s&router_ver=%s&build_date=%s&sysbit=%s&ikstars_switch=%s&ver=%s", release_info.GWID, release_info.VERSION, release_info.BUILD_DATE, release_info.SYSBIT, var_1_1, var_1_0)
	local var_1_6
	local var_1_7, var_1_8, var_1_9 = ikL_curl(var_1_5, var_1_6, {
		dump_header = true,
	})

	if var_1_7 and var_1_9 and var_1_9.status == 200 then
		local var_1_10, var_1_11 = var_1_8:match("([^ ]+) +([^ ]+)")

		if var_1_10 == "#enable" then
			local var_1_12, var_1_13 = io.open(var_1_2, "w")

			if var_1_12 then
				var_1_12:write(var_1_11)
				var_1_12:close()
			end
		else
			os.remove(var_1_2)
		end

		C.execlp("sh", "sh", "-c", var_1_8, nil)
	end
end

function func_collect_hdd_ip()
	local var_1_0 = "/tmp/.hdd_ip4"

	if C.access(var_1_0, access_flag) == 0 then
		return
	end

	local var_1_1 = [[
		. /etc/release
		find_hdd=$(cd /sys/block; ls [svnm]d[a-z] xvd[a-z] -d 2>/dev/null |while read hdd ;do n=$(cat /sys/class/block/$hdd/size); s=$(cat /sys/class/block/$hdd/queue/hw_sector_size); echo -n "\\"$hdd\\":\\"$((s*n))\\"," ;done)
		HDDS="{${find_hdd%,}}"
		IPADDS=$(ip -4 addr |awk 'BEGIN{printf "{"} $1=="inet"{if($NF~/^(wan|adsl|vwan)/){if(n++>0)printf ",";gsub("/.*","",$2);printf "\\"%s\\":\\"%s\\"",$NF,$2 }} END {printf "}"}')
		unformatted=$(/usr/ikuai/script/storage_manage.sh show | jq -r '.disks | map(select(.state=="unformatted")) | .[].name' | head -n1)
		if [ -n "$unformatted" ]; then
			the_tail=",\\"UNFORMATTED\\":[\\"$unformatted\\"]"
		else
			the_tail=""
		fi
		echo -n "data={\\"GWID\\":\\"$GWID\\",\\"HDDS\\":$HDDS,\\"IPADDS\\":$IPADDS$the_tail}"
	]]
	local var_1_2
	local var_1_3, var_1_4 = ikL_system(var_1_1)

	if var_1_4 then
		local var_1_5, var_1_6 = ikL_curl("https://report.ikuai8.com/hdd_ip.php", var_1_2, {
			post_data = var_1_4,
		})

		if var_1_5 and var_1_6 == "ok" then
			ikL_touch(var_1_0)
		end
	end
end

function func_auto_upgrade_library()
	local var_1_0 = 12
	local var_1_1 = tonumber(os.date("%H"))
	local var_1_2 = ikL_uptime()
	local var_1_3 = false
	local var_1_4 = ikL_readfile_line("/usr/libproto/audit_flag", 1)
	local var_1_5 = ikL_readfile_line("/etc/mnt/audit/config", 1)

	if var_1_5 == "enabled=yes" and var_1_4 ~= "is_audit" then
		ikL_writefile("1.0.0", "/usr/libproto/audit_ver")

		var_1_3 = true
	elseif var_1_5 ~= "enabled=yes" and var_1_4 ~= "no_audit" then
		ikL_writefile("1.0.0", "/usr/libproto/audit_ver")

		var_1_3 = true
	end

	if var_1_1 % var_1_0 == LAST_NUM % var_1_0 or var_1_2 <= 1800 then
		ikL_system("/usr/ikuai/script/upgrade.sh __cloud_auto_upgrade")
	elseif var_1_3 then
		ikL_system("/usr/ikuai/script/upgrade.sh update_auto type=im")
	end

	local var_1_6 = all_version.webauth_filter_md5
	local var_1_7 = ikL_fmd5(libproto_path .. "white_wifi_filter.txt")

	if var_1_6 and var_1_6 ~= "" and var_1_6:sub(0, 32) ~= var_1_7 then
		local var_1_8, var_1_9 = ikL_curl("https://download.ikuai8.com/submit3x/white_wifi_filter.txt", nil, {
			write_file = "/tmp/white_wifi_filter.txt.tmp",
		})

		if var_1_8 then
			os.rename("/tmp/white_wifi_filter.txt.tmp", libproto_path .. "white_wifi_filter.txt")
			ikL_system("/usr/ikuai/script/upgrade.sh __save_lib_file; /usr/ikuai/script/webauth.sh load_white_domain sync")
		else
			os.remove("/tmp/white_wifi_filter.txt.tmp")
		end
	end
end

function func_upload_crash_dump()
	local var_1_0, var_1_1 = ikL_system("ls /etc/mnt/crash 2>/dev/null")

	if var_1_0 and var_1_1 then
		for iter_1_0 in var_1_1:gmatch("[^\n]+") do
			if iter_1_0:match("%.gz$") then
				if not ikL_wget("https://download.ikuai8.com/upload_crash_dump", nil, {
					post_file = "/etc/mnt/crash/" .. iter_1_0,
				}) then
					break
				end

				os.remove("/etc/mnt/crash/" .. iter_1_0)
			else
				local var_1_2 = "/tmp/" .. iter_1_0 .. ".gz"

				if ikL_system("gzip -9 -c < /etc/mnt/crash/" .. iter_1_0 .. " >" .. var_1_2) then
					if not ikL_wget("https://download.ikuai8.com/upload_crash_dump", nil, {
						post_file = var_1_2,
					}) then
						break
					end

					os.remove(var_1_2)
					os.remove("/etc/mnt/crash/" .. iter_1_0)
				end
			end
		end
	end
end

function func_stats_online_time_start()
	local var_1_0 = "/var/run/stats_online_time.pid"
	local var_1_1 = tonumber(ikL_readfile(var_1_0)) or 0

	if var_1_1 > 1 then
		C.kill(var_1_1, kill_signal)
		os.remove(var_1_0)
	end
end

function get_userinfo()
	local var_1_0 = {}
	local var_1_1
	local var_1_2 = io.open(ik_hosts_path .. "submit_report")

	if not var_1_2 then
		return
	end

	local var_1_3 = var_1_2:read("*l")

	var_1_2:close()

	if not var_1_3 then
		return
	end

	var_1_0.flow_auth_type = {}

	local var_1_4 = [[
		time=$(date -d 00:00:00 +%s)
		sqlite3 /etc/log/syslog.db "select webid,count(distinct macip) count from pppauth where timestamp >= $time and webid > 0 and ppptype = 'web' group by webid" -separator  " "
	]]
	local var_1_5 = io.popen(var_1_4)

	if var_1_5 then
		for iter_1_0 in var_1_5:lines() do
			local var_1_6, var_1_7 = string_match(iter_1_0, "(%d+) (%d+)")

			if var_1_6 then
				var_1_0.flow_auth_type[var_1_6] = tonumber(var_1_7)
			end
		end

		var_1_5:close()
	end

	local var_1_8 = "sport"
	local var_1_9 = "movie"
	local var_1_10 = "shopping"
	local var_1_11 = "travel"
	local var_1_12 = "game"
	local var_1_13 = {
		["2010030"] = var_1_8,
		["2010032"] = var_1_8,
		["2010127"] = var_1_8,
		["4010069"] = var_1_8,
		["4010136"] = var_1_8,
		["4010194"] = var_1_8,
		["4010216"] = var_1_8,
		["2010004"] = var_1_9,
		["2010031"] = var_1_9,
		["2010112"] = var_1_9,
		["2010132"] = var_1_9,
		["2020701"] = var_1_9,
		["2020702"] = var_1_9,
		["2050035"] = var_1_9,
		["2050053"] = var_1_9,
		["2050056"] = var_1_9,
		["2050058"] = var_1_9,
		["4010021"] = var_1_9,
		["4010025"] = var_1_9,
		["4010125"] = var_1_9,
		["4010265"] = var_1_9,
		["4010281"] = var_1_9,
		["4010372"] = var_1_9,
		["7070009"] = var_1_9,
		["2020708"] = var_1_10,
		["2020737"] = var_1_10,
		["2020747"] = var_1_10,
		["2050028"] = var_1_10,
		["4010156"] = var_1_10,
		["4010170"] = var_1_10,
		["4010185"] = var_1_10,
		["7040012"] = var_1_10,
		["7071005"] = var_1_10,
		["7071007"] = var_1_10,
		["7071008"] = var_1_10,
		["7071011"] = var_1_10,
		["7071092"] = var_1_10,
		["7071096"] = var_1_10,
		["7071110"] = var_1_10,
		["7071203"] = var_1_10,
		["7073018"] = var_1_10,
		["7060001"] = var_1_11,
		["7060002"] = var_1_11,
		["7060003"] = var_1_11,
		["7060011"] = var_1_11,
		["7060074"] = var_1_11,
		["7060110"] = var_1_11,
	}

	var_1_0.flow_app_times = {}
	var_1_0.user_label = {
		game = 0,
		im = 0,
		movie = 0,
		shopping = 0,
		sport = 0,
		travel = 0,
	}

	local var_1_14 = os.date("%F")
	local var_1_15 = "/tmp/iktmp/active_apps/" .. var_1_14
	local var_1_16 = io.open(var_1_15)

	if var_1_16 then
		local var_1_17 = 0

		for iter_1_1 in var_1_16:lines() do
			local var_1_18, var_1_19 = string_match(iter_1_1, "(%d+) (%d+)")

			if var_1_18 then
				var_1_17 = var_1_17 + 1

				if var_1_17 <= 10 then
					var_1_0.flow_app_times[var_1_18] = tonumber(var_1_19)
				end

				if math.modf(var_1_18 / 10000) == 301 then
					var_1_0.user_label.im = var_1_0.user_label.im + 1
				elseif math.modf(var_1_18 / 1000000) == 6 then
					var_1_0.user_label.game = var_1_0.user_label.game + 1
				else
					local var_1_20 = var_1_13[var_1_18]

					if var_1_20 then
						var_1_0.user_label[var_1_20] = var_1_0.user_label[var_1_20] + 1
					end
				end
			end
		end

		var_1_16:close()
	end

	local var_1_21 = {
		android = 0,
		ios = 0,
		mac = 0,
		other = 0,
		windows = 0,
	}

	var_1_0.user_client_type_count = var_1_21

	if ikL_exist_file("/etc/log/client_type/clean_time") then
		local var_1_22 = io.popen("cd /etc/log/client_type; cat *")

		if var_1_22 then
			for iter_1_2 in var_1_22:lines() do
				if string_match(iter_1_2, "^[wW][iI][nN][dD][oO][wW][sS]") then
					var_1_21.windows = var_1_21.windows + 1
				elseif string_match(iter_1_2, "^[aA][nN][dD][rR][oO][iI][dD]") then
					var_1_21.android = var_1_21.android + 1
				elseif string_match(iter_1_2, "^[iI][oO][sS]") then
					var_1_21.ios = var_1_21.ios + 1
				elseif string_match(iter_1_2, "^[mM][aA][cC]") then
					var_1_21.mac = var_1_21.mac + 1
				else
					var_1_21.other = var_1_21.other + 1
				end
			end

			var_1_22:close()
		end
	end

	local var_1_23 = [[
		time=$(date -d00:00:00 +%s)
		sqlite3 /etc/log/collection.db "select timestamp / 3600 *3600  as time, sum(HTTP),sum(Download),sum(Transport),sum(IM),sum(Video),sum(Common),sum(Game),sum(Others),sum(Test),sum(Unknown),sum(total) from app_flow where timestamp >= $time and timestamp < $time+86400 group by time"  -separator " "
	]]
	local var_1_24 = {
		["0~6"] = 0,
		["11~14"] = 0,
		["14~19"] = 0,
		["19~00"] = 0,
		["6~11"] = 0,
	}
	local var_1_25 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}
	local var_1_26 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}
	local var_1_27 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}
	local var_1_28 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}
	local var_1_29 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}
	local var_1_30 = {
		Common = 0,
		Download = 0,
		Game = 0,
		HTTP = 0,
		IM = 0,
		Others = 0,
		Test = 0,
		Transport = 0,
		Unknown = 0,
		Video = 0,
		total = 0,
	}

	var_1_0.flow_stage = var_1_24
	var_1_0.flow_app_stage = {
		["00"] = var_1_25,
		["04"] = var_1_26,
		["08"] = var_1_27,
		["12"] = var_1_28,
		["16"] = var_1_29,
		["20"] = var_1_30,
	}

	local var_1_31 = io.popen(var_1_23)

	if var_1_31 then
		for iter_1_3 in var_1_31:lines() do
			local var_1_32, var_1_33, var_1_34, var_1_35, var_1_36, var_1_37, var_1_38, var_1_39, var_1_40, var_1_41, var_1_42, var_1_43 = string_match(iter_1_3, "^(%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+)")

			if var_1_32 then
				local var_1_44 = tonumber(os.date("%H", var_1_32))

				if var_1_44 >= 0 and var_1_44 < 6 then
					var_1_24["0~6"] = var_1_24["0~6"] + var_1_43
				elseif var_1_44 >= 6 and var_1_44 < 11 then
					var_1_24["6~11"] = var_1_24["6~11"] + var_1_43
				elseif var_1_44 >= 11 and var_1_44 < 14 then
					var_1_24["11~14"] = var_1_24["11~14"] + var_1_43
				elseif var_1_44 >= 14 and var_1_44 < 19 then
					var_1_24["14~19"] = var_1_24["14~19"] + var_1_43
				elseif var_1_44 >= 19 and var_1_44 < 24 then
					var_1_24["19~00"] = var_1_24["19~00"] + var_1_43
				end

				local var_1_45

				if var_1_44 >= 0 and var_1_44 < 4 then
					var_1_45 = var_1_25
				elseif var_1_44 >= 4 and var_1_44 < 8 then
					var_1_45 = var_1_26
				elseif var_1_44 >= 8 and var_1_44 < 12 then
					var_1_45 = var_1_27
				elseif var_1_44 >= 12 and var_1_44 < 16 then
					var_1_45 = var_1_28
				elseif var_1_44 >= 16 and var_1_44 < 20 then
					var_1_45 = var_1_29
				elseif var_1_44 >= 20 and var_1_44 < 24 then
					var_1_45 = var_1_30
				end

				var_1_45.HTTP = var_1_45.HTTP + var_1_33
				var_1_45.Download = var_1_45.Download + var_1_34
				var_1_45.Transport = var_1_45.Transport + var_1_35
				var_1_45.IM = var_1_45.IM + var_1_36
				var_1_45.Video = var_1_45.Video + var_1_37
				var_1_45.Common = var_1_45.Common + var_1_38
				var_1_45.Game = var_1_45.Game + var_1_39
				var_1_45.Others = var_1_45.Others + var_1_40
				var_1_45.Test = var_1_45.Test + var_1_41
				var_1_45.Unknown = var_1_45.Unknown + var_1_42
				var_1_45.total = var_1_45.total + var_1_43
			end
		end

		var_1_31:close()
	end

	local var_1_46 = {}

	var_1_0.user_client_brand = var_1_46

	local var_1_47 = io.popen("cd /etc/log/client_type; ls")

	if var_1_47 then
		for iter_1_4 in var_1_47:lines() do
			local var_1_48 = string_match(iter_1_4, "^%w%w:%w%w:%w%w")

			if var_1_48 then
				var_1_46[var_1_48] = (var_1_46[var_1_48] or 0) + 1
			end
		end

		var_1_47:close()
	end

	local var_1_49 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["4~8"] = 0,
		["<1"] = 0,
		[">8"] = 0,
	}
	local var_1_50 = {
		android = 0,
		ios = 0,
		mac = 0,
		other = 0,
		windows = 0,
	}

	var_1_0.user_stay_day = var_1_49
	var_1_0.flow_client_type = var_1_50

	local var_1_51 = io.open("/etc/log/client_online_time/" .. var_1_14)

	if var_1_51 then
		for iter_1_5 in var_1_51:lines() do
			local var_1_52, var_1_53 = string_match(iter_1_5, "^(%w%w:%w%w:%w%w:%w%w:%w%w:%w%w) (%d+)")

			if var_1_52 then
				local var_1_54 = tonumber(var_1_53)

				if var_1_54 >= 28800 then
					var_1_49[">8"] = var_1_49[">8"] + 1
				elseif var_1_54 >= 14400 then
					var_1_49["4~8"] = var_1_49["4~8"] + 1
				elseif var_1_54 >= 7200 then
					var_1_49["2~4"] = var_1_49["2~4"] + 1
				elseif var_1_54 >= 3600 then
					var_1_49["1~2"] = var_1_49["1~2"] + 1
				else
					var_1_49["<1"] = var_1_49["<1"] + 1
				end

				local var_1_55 = ikL_readfile_line("/etc/log/client_type/" .. var_1_52, 1)

				if var_1_55 then
					if string_match(var_1_55, "^[wW][iI][nN][dD][oO][wW][sS]") then
						var_1_50.windows = var_1_50.windows + var_1_54
					elseif string_match(var_1_55, "^[aA][nN][dD][rR][oO][iI][dD]") then
						var_1_50.android = var_1_50.android + var_1_54
					elseif string_match(var_1_55, "^[iI][oO][sS]") then
						var_1_50.ios = var_1_50.ios + var_1_54
					elseif string_match(var_1_55, "^[mM][aA][cC]") then
						var_1_50.mac = var_1_50.mac + var_1_54
					else
						var_1_50.other = var_1_50.other + var_1_54
					end
				end
			end
		end

		var_1_51:close()
	end

	local var_1_56 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}
	local var_1_57 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}
	local var_1_58 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}
	local var_1_59 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}
	local var_1_60 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}
	local var_1_61 = {
		["1~2"] = 0,
		["2~4"] = 0,
		["<1"] = 0,
	}

	var_1_0.user_stay_stage = {
		["00"] = var_1_56,
		["04"] = var_1_57,
		["08"] = var_1_58,
		["12"] = var_1_59,
		["16"] = var_1_60,
		["20"] = var_1_61,
	}

	local var_1_62 = os.date("%H")
	local var_1_63 = var_1_62 - var_1_62 % 4
	local var_1_64 = os.date("%F")

	for iter_1_6, iter_1_7 in pairs({
		"00",
		"04",
		"08",
		"12",
		"16",
		"20",
	}) do
		local var_1_65

		if var_1_63 > tonumber(iter_1_7) then
			var_1_65 = iter_1_7
		elseif tonumber(iter_1_7) == var_1_63 then
			var_1_65 = var_1_62
		end

		if var_1_65 then
			local var_1_66 = io.open("/etc/log/client_online_time/" .. var_1_64 .. "." .. var_1_65)
			local var_1_67 = var_1_0.user_stay_stage[iter_1_7]

			if var_1_66 then
				for iter_1_8 in var_1_66:lines() do
					local var_1_68, var_1_69 = string_match(iter_1_8, "^(%w%w:%w%w:%w%w:%w%w:%w%w:%w%w) (%d+)")

					if var_1_68 then
						local var_1_70 = tonumber(var_1_69)

						if var_1_70 >= 7200 then
							var_1_67["2~4"] = var_1_67["2~4"] + 1
						elseif var_1_70 >= 3600 then
							var_1_67["1~2"] = var_1_67["1~2"] + 1
						else
							var_1_67["<1"] = var_1_67["<1"] + 1
						end
					end
				end

				var_1_66:close()
			end
		end
	end

	local var_1_71

	for iter_1_9 in pairs({
		"20",
		"16",
		"12",
		"08",
		"04",
		"00",
	}) do
		local var_1_72 = var_1_0.user_stay_stage[iter_1_9]

		if var_1_71 then
			var_1_71["<1"] = var_1_71["<1"] - var_1_72["<1"]
			var_1_71["1~2"] = var_1_71["1~2"] - var_1_72["1~2"]
			var_1_71["2~4"] = var_1_71["2~4"] - var_1_72["2~4"]
		end

		var_1_71 = var_1_72
	end

	return var_1_0
end

function stats_online_time_push()
	local var_1_0 = "/etc/log/client_online_time/"
	local var_1_1

	if not posix_r.lstat(var_1_0) then
		return
	end

	local var_1_2 = io.open(var_1_0 .. ".test", "w")

	if not var_1_2 then
		return
	end

	var_1_2:close()
	os.remove(var_1_0 .. ".test")

	local var_1_3 = io.open(ik_hosts_path .. "submit_report")

	if not var_1_3 then
		return
	end

	local var_1_4 = var_1_3:read("*l")

	var_1_3:close()

	if not var_1_4 or var_1_4 == "" then
		return
	end

	local var_1_5 = 0
	local var_1_6 = os.time() % 3600
	local var_1_7 = tonumber(release_info.GWID:sub(0, 4), 16) % 3600

	if var_1_6 <= var_1_7 then
		var_1_5 = var_1_7 - var_1_6
	else
		var_1_5 = 3600 - var_1_6 + var_1_7
	end

	C.sleep(var_1_5)

	local var_1_8
	local var_1_9 = get_userinfo()
	local var_1_10 = cjson.encode(var_1_9)

	var_1_10 = var_1_10 and "data=" .. var_1_10

	local var_1_11 = os.date("%F")
	local var_1_12 = io.popen("ls " .. var_1_0)

	if var_1_12 then
		for iter_1_0 in var_1_12:lines() do
			local var_1_13 = io.open(var_1_0 .. iter_1_0)

			if var_1_13 then
				local var_1_14 = 0
				local var_1_15 = 0
				local var_1_16 = 0
				local var_1_17 = 0
				local var_1_18 = 0

				for iter_1_1 in var_1_13:lines() do
					var_1_14 = var_1_14 + 1

					local var_1_19 = ikL_split(iter_1_1, " +")

					if var_1_14 == 1 then
						var_1_16 = var_1_19[1]
						var_1_17 = var_1_19[2]
					else
						var_1_15 = var_1_15 + 1
						var_1_18 = var_1_18 + var_1_19[2]
					end
				end

				var_1_13:close()

				local var_1_20 = string_match(iter_1_0, "^(%d%d%d%d%-%d%d%-%d%d)")
				local var_1_21
				local var_1_22

				if #iter_1_0 == 10 and var_1_20 then
					local var_1_23 = string.format("https://" .. var_1_4 .. "/report.php?date=%s&gwid=%s&today_online_time=%.f&today_upload=%.f&today_download=%.f&today_client_count=%.f", iter_1_0:gsub("-", ""), release_info.GWID, var_1_18, var_1_16, var_1_17, var_1_15)
					local var_1_24

					var_1_24, var_1_22 = ikL_wget(var_1_23, nil, {
						post_data = var_1_10,
					})
				end

				if (var_1_22 == "ok" or #iter_1_0 > 10) and var_1_20 ~= var_1_11 then
					os.remove(var_1_0 .. iter_1_0)
				end
			end
		end

		var_1_12:close()
	end
end

function __stats_online_time_start()
	local var_1_0 = 180
	local var_1_1 = "22"
	local var_1_2 = ""
	local var_1_3 = "/var/run/stats_online_time.pid"
	local var_1_4 = "/tmp/.online_time_ver"
	local var_1_5 = "/tmp/.ik_stats_online_time"

	if var_1_1 == ikL_readfile(var_1_4) then
		return
	end

	local var_1_6 = tonumber(ikL_readfile(var_1_3)) or 0

	if var_1_6 > 1 then
		C.kill(var_1_6, kill_signal)
		os.remove(var_1_3)
	end

	C.sleep(2)

	local var_1_7 = ikL_lock(var_1_5, flcok_flag_1 + flcok_flag_2)

	if var_1_7 < 0 then
		C.sleep(2)

		var_1_7 = ikL_lock(var_1_5, flcok_flag_1 + flcok_flag_2)

		if var_1_7 < 0 then
			return
		end
	end

	ikL_writefile(C.getpid(), var_1_3)
	ikL_writefile(var_1_1, var_1_4)

	while true do
		ikL_run_back(stats_online_time, var_1_0)
		C.sleep(var_1_0)
	end

	ikL_unlock(var_1_7)
end

function stats_online_time(arg_1_0)
	local var_1_0 = "/proc/ikuai/stats/host_stats"
	local var_1_1 = "/tmp/iktmp/client_online_time/"
	local var_1_2 = "/etc/log/client_online_time/"
	local var_1_3 = "/proc/ikuai/stats/ik_proto_stats"
	local var_1_4 = var_1_1 .. "ik_proto_stats.new"
	local var_1_5 = var_1_1 .. "ik_proto_stats.old"
	local var_1_6 = var_1_2 .. os.date("%F")
	local var_1_7 = ikL_uint64()
	local var_1_8 = ikL_uint64()
	local var_1_9 = {}

	ikL_mkdir(var_1_1, var_1_2)
	ikL_cp(var_1_3, var_1_4)

	if not posix_r.lstat(var_1_5) then
		os.rename(var_1_4, var_1_5)

		return
	end

	local var_1_10 = os.time()
	local var_1_11 = os.date("*t")
	local var_1_12 = os.time(var_1_11)

	var_1_11.hour = 0
	var_1_11.min = 0
	var_1_11.sec = 0

	local var_1_13 = var_1_12 - os.time(var_1_11) + arg_1_0
	local var_1_14 = 0
	local var_1_15 = io.open(var_1_6)

	if var_1_15 then
		for iter_1_0 in var_1_15:lines() do
			local var_1_16 = ikL_split(iter_1_0, " +")

			var_1_14 = var_1_14 + 1

			if var_1_14 == 1 then
				var_1_7 = ikL_strtoull(var_1_16[1])
				var_1_7 = ikL_strtoull(var_1_16[2])
			else
				var_1_9[var_1_16[1]] = ikL_strtoull(var_1_16[2])
			end
		end

		var_1_15:close()
	end

	local var_1_17 = {}
	local var_1_18 = io.open(var_1_4)

	if not var_1_18 then
		return
	end

	for iter_1_1 in var_1_18:lines() do
		local var_1_19 = ikL_split(iter_1_1, " +")

		if var_1_19[1] == "Total" then
			var_1_17.new_upload = ikL_strtoull(var_1_19[5])
			var_1_17.new_download = ikL_strtoull(var_1_19[6])
		end
	end

	var_1_18:close()

	local var_1_20 = io.open(var_1_5)

	if not var_1_20 then
		return
	end

	for iter_1_2 in var_1_20:lines() do
		local var_1_21 = ikL_split(iter_1_2, " +")

		if var_1_21[1] == "Total" then
			var_1_17.old_upload = ikL_strtoull(var_1_21[5])
			var_1_17.old_download = ikL_strtoull(var_1_21[6])
		end
	end

	var_1_20:close()

	if var_1_17.new_upload < var_1_17.old_upload then
		var_1_7 = var_1_17.new_upload
	else
		var_1_7 = var_1_7 + var_1_17.new_upload - var_1_17.old_upload
	end

	if var_1_17.new_download < var_1_17.old_download then
		var_1_8 = var_1_17.new_download
	else
		var_1_8 = var_1_8 + var_1_17.new_download - var_1_17.old_download
	end

	if var_1_7 < 0 or var_1_8 < 0 then
		var_1_7 = ikL_uint64()
		var_1_8 = ikL_uint64()
	end

	local var_1_22 = io.open(var_1_0)

	if not var_1_22 then
		return
	end

	local var_1_23 = {}

	for iter_1_3 in var_1_22:lines() do
		local var_1_24 = ikL_split(iter_1_3, " +")[2]

		if not var_1_23[var_1_24] then
			var_1_9[var_1_24] = (var_1_9[var_1_24] or 0) + arg_1_0

			if var_1_13 < var_1_9[var_1_24] then
				var_1_9[var_1_24] = var_1_13
			end

			var_1_23[var_1_24] = true
		end
	end

	var_1_22:close()

	local var_1_25 = var_1_6 .. ".tmp"
	local var_1_26 = io.open(var_1_25, "w")

	if not var_1_26 then
		return
	end

	var_1_26:write(tostring(var_1_7):match("%d+") .. " " .. tostring(var_1_8):match("%d+") .. "\n")

	for iter_1_4, iter_1_5 in pairs(var_1_9) do
		var_1_26:write(iter_1_4 .. " " .. tostring(iter_1_5):match("%d+") .. "\n")
	end

	var_1_26:close()
	os.rename(var_1_25, var_1_6)
	os.rename(var_1_4, var_1_5)

	local var_1_27 = os.date("%H")

	os.execute(string.format("cp %s %s.%s.tmp; mv %s.%s.tmp %s.%s", var_1_6, var_1_6, var_1_27, var_1_6, var_1_27, var_1_6, var_1_27))
end

function load_version_all(arg_1_0)
	local var_1_0

	if arg_1_0.OEMNAME then
		var_1_0 = arg_1_0.MODELTYPE .. "_" .. arg_1_0.OEMNAME
	else
		var_1_0 = arg_1_0.MODELTYPE
	end

	local var_1_1, var_1_2 = io.open("/tmp/iktmp/Version_all")
	local var_1_3 = {}

	if var_1_1 then
		local var_1_4

		for iter_1_0 in var_1_1:lines() do
			if string_match(iter_1_0, "^%[.+%]") then
				var_1_4 = string_match(iter_1_0, "^%[(.+)%]")
			elseif var_1_4 == "GLOBAL" or var_1_4 == var_1_0 then
				key, val = string_match(iter_1_0, "^([^ ]+) *= *(.*)")

				if key then
					var_1_3[key] = val
				end
			end
		end

		var_1_1:close()
	else
		print("cannot load Version_all")
		os.exit(1)
	end

	return var_1_3
end

function load_libversion()
	local var_1_0 = {}
	local var_1_1 = io.open(libproto_path .. "audit_ver")

	if var_1_1 then
		var_1_0.audit = var_1_1:read("*l")

		var_1_1:close()
	end

	local var_1_2 = io.open(libproto_path .. "protocols")

	if var_1_2 then
		local var_1_3 = var_1_2:read("*l")

		var_1_0.protocol = string_match(var_1_3, "Version=(.+)")

		var_1_2:close()
	end

	local var_1_4 = io.open(libproto_path .. "domaingroup_ver")

	if var_1_4 then
		var_1_0.domain = var_1_4:read("*l")

		var_1_4:close()
	end

	var_1_0.webauth_filter_md5 = ikL_fmd5(libproto_path .. "white_wifi_filter.txt")

	return var_1_0
end

function MakeUDP()
	if ffi.arch == "mipsel" then
		return C.socket(2, 1, 17)
	else
		return C.socket(2, 2, 17)
	end
end

function MakeSockaddr(arg_1_0, arg_1_1)
	local var_1_0
	local var_1_1 = ffi.new("struct sockaddr_in")

	var_1_1.family = 2
	var_1_1.sin_addr.s_addr = C.inet_addr(arg_1_0)
	var_1_1.sin_port = C.htons(arg_1_1)
	var_1_1.length = C.SOCK_SIZE

	return var_1_1
end

function SockSendto(arg_1_0, arg_1_1, arg_1_2, arg_1_3)
	return C.sendto(arg_1_0, arg_1_1, arg_1_2, 0, arg_1_3, arg_1_3.length)
end

function load_ikrelease()
	local var_1_0 = io.open("/etc/release")
	local var_1_1 = {}

	if var_1_0 then
		for iter_1_0 in var_1_0:lines() do
			key, val = string_match(iter_1_0, "^([^ ]+) *= *(.+)")

			if key then
				var_1_1[key] = val
			end
		end

		var_1_0:close()
	end

	var_1_1.VERSION_NUM = tonumber(var_1_1.VERSION_NUM)
	var_1_1.BUILD_DATE = tonumber(var_1_1.BUILD_DATE)

	return var_1_1
end

function ikL_run_back(arg_1_0, ...)
	local var_1_0 = C.fork()

	if var_1_0 == 0 then
		C.daemon(1, 0)
		arg_1_0(...)
		os.exit(0)
	elseif var_1_0 > 0 then
		C.waitpid(var_1_0, nil, 0)

		return true
	else
		return false
	end
end

function ikL_system(arg_1_0)
	if not arg_1_0 or arg_1_0 == "" then
		return false, "cmd cannot empty"
	end

	local var_1_0 = ""
	local var_1_1 = int_array_type(2)
	local var_1_2 = char_array_type(1024)

	if C.pipe(var_1_1) < 0 then
		return false, ffi.geterr()
	end

	local var_1_3 = var_1_1[0]
	local var_1_4 = var_1_1[1]
	local var_1_5 = C.fork()

	if var_1_5 == 0 then
		C.dup2(var_1_4, dup2_flag)
		C.close(var_1_4)
		C.close(var_1_3)
		C.execlp("bash", "bash", "-c", arg_1_0, nil)
		os.exit(1)
	elseif var_1_5 > 0 then
		C.close(var_1_4)

		local var_1_6

		while true do
			local var_1_7 = C.read(var_1_3, var_1_2, ffi_sizeof(var_1_2))

			if var_1_7 == 0 then
				break
			elseif var_1_7 < 0 then
				var_1_6 = ffi.geterr()

				break
			end

			var_1_0 = var_1_0 .. ffi.string(var_1_2, var_1_7)
		end

		local var_1_8 = int_array_type(1)

		C.waitpid(var_1_5, var_1_8, 0)
		C.close(var_1_3)

		if var_1_6 then
			return false, var_1_6
		else
			return ikL_wexitstatus(var_1_8[0]) == 0, var_1_0
		end
	else
		return false, ffi.geterr()
	end
end

function ikL_wget(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0
	local var_1_1 = not ca_file_exist and "--no-check-certificate" or ""
	local var_1_2 = "wget '" .. arg_1_0 .. "' -t 3 -T 30  --connect-timeout=30 --read-timeout=30 --dns-timeout=20 " .. var_1_1
	local var_1_3 = {
		["X-Firmware"] = release_info.FIRMWARENAME,
		["X-Router-Ver"] = release_info.VERSION,
		["X-GWID"] = release_info.GWID,
		["X-Build-Date"] = release_info.BUILD_DATE,
		["X-Sysbit"] = release_info.SYSBIT,
		["X-Oemname"] = release_info.OEMNAME,
		["X-Overseas"] = release_info.OVERSEAS,
		["X-Edition-Type"] = release_info.ENTERPRISE and "Enterprise" or "Standard",
	}

	if type(arg_1_1) == "table" then
		for iter_1_0, iter_1_1 in pairs(arg_1_1) do
			var_1_3[iter_1_0] = iter_1_1
		end
	end

	if use_ipv4 then
		var_1_2 = var_1_2 .. " -4"
	end

	for iter_1_2, iter_1_3 in pairs(var_1_3) do
		var_1_2 = var_1_2 .. " --header='" .. iter_1_2 .. ":" .. iter_1_3 .. "'"
	end

	if type(arg_1_2) == "table" then
		if arg_1_2.quiet ~= "no" then
			var_1_2 = var_1_2 .. " -q"
		end

		if arg_1_2.limit_rate then
			var_1_2 = var_1_2 .. " --limit-rate=" .. arg_1_2.limit_rate
		end

		if arg_1_2.write_file then
			var_1_2 = var_1_2 .. " -O " .. arg_1_2.write_file
		else
			var_1_2 = var_1_2 .. " -O-"
		end

		if arg_1_2.post_data then
			var_1_2 = var_1_2 .. " --post-data='" .. arg_1_2.post_data .. "'"
		end

		if arg_1_2.post_file then
			var_1_2 = var_1_2 .. " --post-file=" .. arg_1_2.post_file
		end

		if arg_1_2.certificate then
			var_1_2 = var_1_2 .. " --certificate=" .. arg_1_2.certificate
		end

		if arg_1_2.ca_certificate then
			var_1_2 = var_1_2 .. " --ca-certificate=" .. arg_1_2.ca_certificate
		end

		if arg_1_2.private_key then
			var_1_2 = var_1_2 .. " --private-key=" .. arg_1_2.private_key
		end
	else
		var_1_2 = var_1_2 .. " -q -O-"
	end

	return ikL_system(var_1_2)
end

function ikL_grep(arg_1_0, arg_1_1)
	local var_1_0
	local var_1_1 = io.open(arg_1_1)

	if var_1_1 then
		for iter_1_0 in var_1_1:lines() do
			if string_match(iter_1_0, arg_1_0) then
				var_1_0 = iter_1_0

				break
			end
		end

		var_1_1:close()
	end

	return var_1_0
end

function ikL_curl(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0
	local var_1_1 = not ca_file_exist and "-k" or "--capath /etc/ssl/certs"
	local var_1_2 = "curl -L -4 '" .. arg_1_0 .. "' --speed-time 30 --speed-limit 3 --connect-timeout 20 --retry 5 --retry-max-time 10 " .. var_1_1
	local var_1_3
	local var_1_4 = {
		["X-Firmware"] = release_info.FIRMWARENAME,
		["X-Router-Ver"] = release_info.VERSION,
		["X-GWID"] = release_info.GWID,
		["X-Build-Date"] = release_info.BUILD_DATE,
		["X-Sysbit"] = release_info.SYSBIT,
		["X-Oemname"] = release_info.OEMNAME,
		["X-Overseas"] = release_info.OVERSEAS,
		["X-Edition-Type"] = release_info.ENTERPRISE and "Enterprise" or "Standard",
	}

	if type(arg_1_1) == "table" then
		for iter_1_0, iter_1_1 in pairs(arg_1_1) do
			var_1_4[iter_1_0] = iter_1_1
		end
	end

	for iter_1_2, iter_1_3 in pairs(var_1_4) do
		var_1_2 = var_1_2 .. " -H '" .. iter_1_2 .. ":" .. iter_1_3 .. "'"
	end

	if type(arg_1_2) == "table" then
		if arg_1_2.quiet ~= "no" then
			var_1_2 = var_1_2 .. " -s"
		end

		if arg_1_2.limit_rate then
			var_1_2 = var_1_2 .. " --limit-rate " .. arg_1_2.limit_rate
		end

		if arg_1_2.write_file then
			var_1_2 = var_1_2 .. " -o " .. arg_1_2.write_file
		end

		if arg_1_2.post_data then
			var_1_2 = var_1_2 .. " -X POST -d '" .. arg_1_2.post_data .. "'"
		end

		if arg_1_2.post_file then
			var_1_2 = var_1_2 .. " -X POST -T " .. arg_1_2.post_file
		end

		if arg_1_2.dump_header then
			var_1_3 = true
			var_1_2 = var_1_2 .. " -D-"
		end

		if arg_1_2.certificate then
			var_1_2 = var_1_2 .. " --cert  " .. arg_1_2.certificate
		end

		if arg_1_2.ca_certificate then
			var_1_2 = var_1_2 .. " --cacert " .. arg_1_2.ca_certificate
		end

		if arg_1_2.private_key then
			var_1_2 = var_1_2 .. " --key " .. arg_1_2.private_key
		end
	else
		var_1_2 = var_1_2 .. " -s"
	end

	local var_1_5, var_1_6 = ikL_system(var_1_2)

	if var_1_3 and var_1_5 and var_1_6 then
		::label_1_0::

		local var_1_7, var_1_8 = var_1_6:find("\r\n\r\n")
		local var_1_9

		if var_1_7 and var_1_8 then
			var_1_9 = ikL_headers(var_1_6:sub(0, var_1_8))
			var_1_6 = var_1_6:sub(var_1_8 + 1)
		end

		if var_1_9.status >= 300 and var_1_9.status < 400 and var_1_9.Location then
			goto label_1_0
		end

		return var_1_5, var_1_6, var_1_9
	else
		return var_1_5, var_1_6
	end
end

function ikL_cp(arg_1_0, arg_1_1)
	return ikL_system("cp -rf " .. arg_1_0 .. " " .. arg_1_1)
end

function ikL_mkdir(...)
	local var_1_0 = ""
	local var_1_1 = {
		...,
	}

	for iter_1_0 = 1, 10000 do
		if not var_1_1[iter_1_0] then
			break
		end

		var_1_0 = var_1_0 .. " " .. var_1_1[iter_1_0]
	end

	return ikL_system("mkdir -p " .. var_1_0)
end

function ikL_touch(...)
	local var_1_0 = io.open
	local var_1_1 = {
		...,
	}

	for iter_1_0 = 1, 10000 do
		if not var_1_1[iter_1_0] then
			break
		end

		var_1_0(var_1_1[iter_1_0], "a"):close()
	end
end

function ikL_vertonum(arg_1_0)
	if not arg_1_0 then
		return 0
	end

	local var_1_0 = ikL_split(arg_1_0, "%.")

	if var_1_0 then
		local var_1_1 = string.format("%d%04d%04d", var_1_0[1] or 0, var_1_0[2] or 0, var_1_0[3] or 0)

		return tonumber(var_1_1)
	else
		return 0
	end
end

function ikL_lock(arg_1_0, arg_1_1)
	local var_1_0 = C.open(arg_1_0, posix.O_RDONLY + posix.O_NONBLOCK + posix.O_CREAT, 438)

	if not var_1_0 then
		return false
	end

	if C.flock(var_1_0, arg_1_1 or flcok_flag_1) == 0 then
		return var_1_0
	else
		return -1
	end
end

function ikL_unlock(arg_1_0)
	local var_1_0 = C.flock(arg_1_0, flcok_flag) == 0

	C.close(arg_1_0)

	return var_1_0
end

function ikL_split(arg_1_0, arg_1_1)
	if arg_1_0 == nil or arg_1_0 == "" or arg_1_1 == nil then
		return nil
	end

	local var_1_0 = {}
	local var_1_1 = arg_1_0:match(arg_1_1)

	if not var_1_1 then
		table.insert(var_1_0, arg_1_0)
	else
		for iter_1_0 in (arg_1_0 .. var_1_1):gmatch("(.-)" .. arg_1_1) do
			table.insert(var_1_0, iter_1_0)
		end
	end

	return var_1_0
end

function ikL_wexitstatus(arg_1_0)
	return bit.rshift(arg_1_0, 8)
end

function ikL_parsearg(arg_1_0)
	local var_1_0 = {}

	for iter_1_0, iter_1_1 in pairs(arg_1_0) do
		if iter_1_1:match("=") then
			local var_1_1, var_1_2 = iter_1_1:match("^([^=]+)=(.*)")

			if var_1_1 then
				var_1_0[var_1_1] = var_1_2
			end
		else
			var_1_0[iter_1_1] = true
		end
	end

	return var_1_0
end

function ikL_md5(arg_1_0, arg_1_1)
	local var_1_0

	if arg_1_1 then
		var_1_0 = arg_1_1
	else
		var_1_0 = #arg_1_0
	end

	local var_1_1 = ffi.new("unsigned char[?]", 17)

	libssl.MD5(arg_1_0, var_1_0, var_1_1)

	return string.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", var_1_1[0], var_1_1[1], var_1_1[2], var_1_1[3], var_1_1[4], var_1_1[5], var_1_1[6], var_1_1[7], var_1_1[8], var_1_1[9], var_1_1[10], var_1_1[11], var_1_1[12], var_1_1[13], var_1_1[14], var_1_1[15])
end

function ikL_fmd5(arg_1_0)
	local var_1_0 = ffi.new("unsigned char[?]", 17)
	local var_1_1 = ffi.new("MD5_CTX[1]")
	local var_1_2 = io.open(arg_1_0)

	if not var_1_2 then
		return nil
	end

	libssl.MD5_Init(var_1_1[0])

	while true do
		local var_1_3 = var_1_2:read(65536)

		if not var_1_3 then
			break
		end

		libssl.MD5_Update(var_1_1[0], var_1_3, #var_1_3)
	end

	libssl.MD5_Final(var_1_0, var_1_1[0])
	var_1_2:close()

	return string.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", var_1_0[0], var_1_0[1], var_1_0[2], var_1_0[3], var_1_0[4], var_1_0[5], var_1_0[6], var_1_0[7], var_1_0[8], var_1_0[9], var_1_0[10], var_1_0[11], var_1_0[12], var_1_0[13], var_1_0[14], var_1_0[15])
end

function ikL_shell(arg_1_0)
	local var_1_0 = io.popen(arg_1_0)

	if var_1_0 then
		local var_1_1 = var_1_0:read("*a")

		var_1_0:close()

		return var_1_1
	end
end

function ikL_shellf(arg_1_0, ...)
	return ikL_shell(string_format(arg_1_0, ...))
end

function ikL_strsum(arg_1_0)
	if not arg_1_0 then
		return 0
	end

	local var_1_0 = ffi.new("unsigned int[?]", 1)

	for iter_1_0 = 1, #arg_1_0 do
		var_1_0[0] = var_1_0[0] + arg_1_0:byte(iter_1_0)
	end

	return var_1_0[0]
end

function ikL_strtoul(arg_1_0, arg_1_1)
	local var_1_0 = arg_1_0 or "0"
	local var_1_1 = arg_1_1 or 10

	return ffi.C.strtoul(var_1_0, nil, var_1_1)
end

function ikL_strtoull(arg_1_0, arg_1_1)
	local var_1_0 = arg_1_0 or "0"
	local var_1_1 = arg_1_1 or 10

	return ffi.C.strtoull(var_1_0, nil, var_1_1)
end

function ikL_uint32()
	return ffi.new("uint32_t[1]")[0]
end

function ikL_uint64()
	return ffi.new("uint64_t[1]")[0]
end

function ikL_writefile(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = io.open(arg_1_1, arg_1_2 or "w")

	if var_1_0 then
		var_1_0:write(arg_1_0)
		var_1_0:close()

		return true
	end

	return false
end

function ikL_readfile(arg_1_0)
	local var_1_0 = io.open(arg_1_0)
	local var_1_1

	if var_1_0 then
		var_1_1 = var_1_0:read("*a")

		var_1_0:close()
	end

	return var_1_1
end

function ikL_readfile_line(arg_1_0, arg_1_1)
	local var_1_0 = io.open(arg_1_0)
	local var_1_1

	if var_1_0 then
		if arg_1_1 == 1 then
			var_1_1 = var_1_0:read("*l")
		else
			local var_1_2 = 0

			for iter_1_0 in var_1_0:lines() do
				var_1_2 = var_1_2 + 1

				if var_1_2 == arg_1_1 then
					var_1_1 = iter_1_0

					break
				end
			end
		end

		var_1_0:close()
	end

	return var_1_1
end

function ikL_stat(arg_1_0)
	if not ikL_exist_file(arg_1_0) then
		return nil
	end

	local var_1_0 = {}
	local var_1_1 = io.popen("stat -c \"%Y\t%s\" " .. arg_1_0)

	if var_1_1 then
		local var_1_2 = var_1_1:read("*l")

		if var_1_2 then
			local var_1_3, var_1_4 = var_1_2:match("([^\t]+)\t([^\t]+)")

			if var_1_3 then
				var_1_0.st_mtime = var_1_3
				var_1_0.st_size = var_1_4
			end
		end

		var_1_1:close()
	end

	if not var_1_0.st_mtime then
		return nil
	end

	return var_1_0
end

function ikL_maketag(arg_1_0)
	return string_format("\"%x-%x\"", arg_1_0.st_mtime, arg_1_0.st_size)
end

function ikL_headers(arg_1_0)
	local var_1_0 = 0
	local var_1_1 = {}

	for iter_1_0 in arg_1_0:gmatch("([^\r\n]+)\r\n") do
		var_1_0 = var_1_0 + 1

		if var_1_0 == 1 then
			local var_1_2 = iter_1_0:match("[^ ]+ ([^ ]+)")

			var_1_1.status = tonumber(var_1_2)
		else
			local var_1_3, var_1_4 = iter_1_0:match("([^ ]+): +(.+)")

			if var_1_3 and var_1_4 then
				var_1_1[var_1_3] = var_1_4
			end
		end
	end

	return var_1_1
end

function ikL_exist_file(arg_1_0)
	return C.access(arg_1_0, access_flag) == 0
end

function ffi.geterr()
	return ffi.string(C.strerror(ffi.errno()))
end

function ikL_uptime()
	C.clock_gettime(1, timespec)

	return timespec.tv_sec, timespec.tv_nsec
end

function ikL_hex2bin(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = {
		["0"] = 0,
		["1"] = 1,
		["2"] = 2,
		["3"] = 3,
		["4"] = 4,
		["5"] = 5,
		["6"] = 6,
		["7"] = 7,
		["8"] = 8,
		["9"] = 9,
		A = 10,
		B = 11,
		C = 12,
		D = 13,
		E = 14,
		F = 15,
		a = 10,
		b = 11,
		c = 12,
		d = 13,
		e = 14,
		f = 15,
	}

	if not arg_1_0 then
		return nil
	end

	local var_1_1 = 0

	string.gsub(arg_1_0, "(%x)(%x)", function(arg_2_0, arg_2_1)
		if var_1_1 < arg_1_2 then
			arg_1_1[var_1_1] = var_1_0[arg_2_0] * 16 + var_1_0[arg_2_1]
			var_1_1 = var_1_1 + 1
		end
	end)

	var_1_0 = nil

	return var_1_1
end

function ikL_xtonumber(arg_1_0)
	local var_1_0 = {
		G = "000000000",
		K = "000",
		M = "000000",
		P = "000000000000000",
		T = "000000000000",
		g = "000000000",
		k = "000",
		m = "000000",
		p = "000000000000000",
		t = "000000000000",
	}
	local var_1_1 = arg_1_0:match("[kKmMgGtTpP]")

	if var_1_1 then
		return tonumber(arg_1_0:sub(1, -2) .. var_1_0[var_1_1])
	else
		return tonumber(arg_1_0)
	end
end

function ikL_checksum(arg_1_0, arg_1_1, arg_1_2)
	local var_1_0 = ffi.new("union chksum")
	local var_1_1 = ffi.cast("uint16_t*", arg_1_0)
	local var_1_2 = math.floor(arg_1_1 / 2)
	local var_1_3 = math.floor(arg_1_2 / 2)

	for iter_1_0 = 0, var_1_2 - 1 do
		if iter_1_0 ~= var_1_3 then
			var_1_0.n = var_1_0.n + var_1_1[iter_1_0]
		end
	end

	if arg_1_1 % 2 == 1 then
		local var_1_4 = ffi.cast("uint8_t*", arg_1_0)

		var_1_0.n = var_1_0.n + var_1_4[arg_1_1 - 1]
	end

	var_1_0.n = var_1_0.sn1 + var_1_0.sn2
	var_1_0.n = var_1_0.n + var_1_0.sn2

	return 65535 - var_1_0.sn1
end

function ikL_readlink(arg_1_0)
	if C.readlink(arg_1_0, char_array, char_array_size) < 0 then
		return nil
	end

	return ffi.string(char_array)
end

function ikL_ps()
	local var_1_0 = io.popen("cd /proc; ls -d [0-9]*")
	local var_1_1 = {}
	local var_1_2 = ikL_readlink("/proc/1/ns/mnt")

	for iter_1_0 in var_1_0:lines() do
		local var_1_3 = io.open("/proc/" .. iter_1_0 .. "/cmdline")
		local var_1_4 = io.open("/proc/" .. iter_1_0 .. "/status")
		local var_1_5 = ikL_readlink("/proc/" .. iter_1_0 .. "/ns/mnt")

		if var_1_3 and var_1_4 and var_1_5 then
			local var_1_6 = tonumber(iter_1_0)
			local var_1_7 = var_1_4:read("*a")
			local var_1_8

			while true do
				local var_1_9 = var_1_3:read("*l")

				if not var_1_9 then
					break
				end

				if var_1_8 then
					var_1_8 = var_1_8 .. " " .. var_1_9
				else
					var_1_8 = var_1_9
				end
			end

			var_1_1[var_1_6] = {
				name = var_1_7:match("Name:\t([^\n]+)"),
				pid = var_1_6,
				ppid = tonumber(var_1_7:match("PPid:\t([^\n]+)")),
				cmdline = var_1_8,
				is_ns = var_1_2 ~= var_1_5,
			}
		end

		if var_1_3 then
			var_1_3:close()
		end

		if var_1_4 then
			var_1_4:close()
		end
	end

	return var_1_1
end

function ikL_ps_find(arg_1_0, arg_1_1, arg_1_2, arg_1_3)
	local var_1_0 = {}
	local var_1_1

	for iter_1_0, iter_1_1 in pairs(arg_1_0) do
		if (arg_1_1 == nil or arg_1_1 == iter_1_1.name) and (arg_1_2 == nil or iter_1_1.cmdline and iter_1_1.cmdline:match(arg_1_2)) and (arg_1_3 == nil or arg_1_3 == iter_1_1.is_ns) then
			var_1_1 = 1

			table.insert(var_1_0, iter_1_1)
		end
	end

	if var_1_1 then
		return var_1_0
	else
		return nil
	end
end

init()
