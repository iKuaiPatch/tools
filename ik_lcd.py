import json

class LCDPacketParser:
    """LCD串口数据包解析器"""
    
    PACKET_SIZE = 48  # 0x30
    
    @staticmethod
    def checksum_to_char(sum_value):
        """将校验和转换为ASCII字符"""
        mod = sum_value % 0x3E
        if mod <= 9:
            return chr(mod + 0x30)  # '0'-'9'
        elif mod < 36:
            return chr(mod + 0x37)  # 'A'-'Z'
        else:
            return chr(mod + 0x3D)  # 'a'-'z'
    
    @staticmethod
    def calculate_checksum_1(data):
        """checksum_1算法 - 用于综合数据命令 (ZWAo)"""
        indices_1 = [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11]
        total = sum(data[i] for i in indices_1)
        
        for i in range(5):
            total += data[12 + i] + data[17 + i]
        
        for i in range(9):
            total += data[22 + i]
        
        for i in range(8):
            total += data[31 + i] + data[39 + i]
        
        total += data[47]
        
        return LCDPacketParser.checksum_to_char(total)
    
    @staticmethod
    def calculate_checksum_2(data):
        """checksum_2算法 - 用于版本/警告/语言等命令"""
        indices = [0, 1, 2, 4, 5, 6, 7]
        total = sum(data[i] for i in indices)
        
        for i in range(8, 47):
            total += data[i]
        
        total += data[47]
        
        return LCDPacketParser.checksum_to_char(total)
    
    @staticmethod
    def calculate_checksum_3(data):
        """checksum_3算法 - 用于设备名称命令"""
        total = sum(data[i] for i in range(48) if i != 3)
        return LCDPacketParser.checksum_to_char(total)
    
    def identify_command(self, packet):
        """识别命令类型"""
        header = packet[:3]
        
        cmd_map = {
            b'ZWA': 'COMPREHENSIVE_DATA', # 综合数据   (-a)
            b'ZWB': 'DEVICE_NAME',        # 设备名称   (-b)
            b'ZWN': 'AP_WARNING',         # AP离线警告 (-n)
            b'ZWC': 'VERSION_INFO',       # 版本信息   (-c)
            b'ZWM': 'SYSTEM_STATUS',      # 系统状态   (-m)
            b'ZWP': 'SCROLLING_SETTING',  # 滚动设置   (-p)
            b'ZWV': 'PAGE_DISPLAY',       # 页面显示   (-v)
            b'ZWY': 'LANGUAGE_SETTING',   # 语言设置   (-y)
        }
        
        cmd_type = cmd_map.get(header, 'UNKNOWN')
        return cmd_type, header.decode('ascii', errors='ignore')
    
    def verify_checksum(self, packet, cmd_type):
        """验证校验和"""
        if len(packet) != self.PACKET_SIZE:
            return False, "Invalid packet size"
        
        checksum = chr(packet[3])
        cmd_prefix = packet[:3]
        
        if cmd_prefix == b'ZWA':
            calculated = self.calculate_checksum_1(packet)
        elif cmd_prefix == b'ZWB':
            calculated = self.calculate_checksum_3(packet)
        else:
            calculated = self.calculate_checksum_2(packet)
        
        is_valid = (checksum == calculated)
        return is_valid, f"Expected: {calculated}, Got: {checksum}"
    
    def parse_null_terminated_fields(self, data):
        """解析NULL分隔的多个字段"""
        fields = []
        current = bytearray()
        
        for byte in data:
            if byte == 0x00:
                if current:
                    try:
                        # 尝试GBK解码
                        text = bytes(current).decode('gbk', errors='ignore')
                        if not text:
                            text = bytes(current).decode('utf-8', errors='ignore')
                        fields.append(text)
                    except:
                        fields.append(bytes(current).hex())
                    current = bytearray()
            else:
                current.append(byte)
        
        # 处理最后一个字段（如果没有以NULL结尾）
        if current:
            try:
                text = bytes(current).decode('gbk', errors='ignore')
                if not text:
                    text = bytes(current).decode('utf-8', errors='ignore')
                fields.append(text)
            except:
                fields.append(bytes(current).hex())
        
        return fields
    
    def parse_device_name(self, data):
        """解析设备名称包 (ZWBx命令)
        
        格式分析：
        [0-3]: 命令头 "ZWBx"
        [4-7]: 固定前缀 "0123"
        [8-47]: 数据区（可能包含多个NULL分隔的字段）
        
        数据区可能包含：
        - 设备名称（第一个字段）
        - 其他系统信息（环境变量残留等）
        """
        prefix = data[4:8].decode('ascii', errors='ignore')
        
        # 从偏移8开始解析所有字段
        all_fields = self.parse_null_terminated_fields(data[8:])
        
        result = {
            'prefix': prefix,
            'device_name': all_fields[0] if all_fields else '',
            'additional_fields': all_fields[1:] if len(all_fields) > 1 else []
        }
        
        # 分析额外字段
        env_vars = {}
        other_info = []
        
        for field in result['additional_fields']:
            if '=' in field:
                # 可能是环境变量
                key, value = field.split('=', 1)
                env_vars[key] = value
            else:
                other_info.append(field)
        
        if env_vars:
            result['environment_variables'] = env_vars
        if other_info:
            result['other_info'] = other_info
        
        return result
    
    def parse_comprehensive_data(self, data):
        """解析综合数据包 (ZWAo命令)"""
        try:
            temp = data[4:7].decode('ascii', errors='ignore').strip('\x00')
            cpu = data[7:9].decode('ascii', errors='ignore').strip('\x00')
            mem = data[9:11].decode('ascii', errors='ignore').strip('\x00')
            upload = data[11:15].decode('ascii', errors='ignore').strip('\x00')
            download = data[15:19].decode('ascii', errors='ignore').strip('\x00')
            uptime = data[19:27].decode('ascii', errors='ignore').strip('\x00')
            users = data[27:35].decode('ascii', errors='ignore').strip('\x00')
            conns = data[35:43].decode('ascii', errors='ignore').strip('\x00')
            link_stat = data[43:44].decode('ascii', errors='ignore').strip('\x00')
            
            return {
                'temperature': f"{temp}°C",
                'cpu_usage': f"{cpu}%",
                'memory_usage': f"{mem}%",
                'upload_speed': upload,
                'download_speed': download,
                'uptime': uptime,
                'online_users': users,
                'connections': conns,
                'link_status': link_stat,
            }
        except Exception as e:
            return {'error': str(e), 'raw': data[4:].hex()}
    
    def parse_version_info(self, data):
        """解析版本信息包 (ZWCm命令)"""
        version = data[8:47].rstrip(b'\x00').decode('ascii', errors='ignore')
        status = data[47]
        return {
            'version': version,
            'update_available': status == ord('1')
        }
    
    def parse_ap_warning(self, data):
        """解析AP警告包 (ZWNx命令)"""
        warning_info = data[8:47].rstrip(b'\x00').decode('utf-8', errors='ignore')
        status = data[47]
        return {
            'warning_info': warning_info,
            'ap_offline': status == ord('1')
        }
    
    def parse_page_display(self, data):
        """解析页面显示包 (ZWVo命令)"""
        return {
            'page1_visible': data[8] == ord('1'),
            'page2_visible': data[9] == ord('1'),
            'page3_visible': data[10] == ord('1'),
            'page4_visible': data[11] == ord('1'),
            'warning_page_visible': data[12] == ord('1'),
        }
    
    def parse_scrolling_setting(self, data):
        """解析滚动设置包 (ZWPo命令)"""
        scrolling = data[47]
        return {
            'scrolling_enabled': scrolling == ord('0'),
            'scrolling_value': chr(scrolling) if scrolling < 128 else scrolling
        }
    
    def parse_language_setting(self, data):
        """解析语言设置包 (ZWYo命令)"""
        lang_code = data[8]
        lang_map = {
            ord('0'): 'English',
            ord('1'): 'Chinese_Traditional',
            ord('2'): 'Chinese_Simplified'
        }
        return {'language': lang_map.get(lang_code, f'Unknown({chr(lang_code)})')}
    
    def parse_system_status(self, data):
        """解析系统状态包 (ZWMo命令)"""
        status_code = data[47]
        status_map = {
            ord('4'): 'REBOOTING',
            ord('5'): 'UPGRADING',
            ord('6'): 'SHUTTING_DOWN'
        }
        return {'system_status': status_map.get(status_code, f'Unknown({chr(status_code)})')}
    
    def parse_packet(self, packet_bytes):
        """解析单个数据包"""
        if len(packet_bytes) != self.PACKET_SIZE:
            return {
                'error': f'Invalid packet size: {len(packet_bytes)} (expected {self.PACKET_SIZE})'
            }
        
        cmd_type, cmd_str = self.identify_command(packet_bytes)
        checksum_valid, checksum_msg = self.verify_checksum(packet_bytes, cmd_type)
        
        result = {
            'command_header': packet_bytes[:4].hex(),
            'command_string': cmd_str,
            'command_type': cmd_type,
            'checksum_valid': checksum_valid,
            'checksum_info': checksum_msg,
            'raw_hex': packet_bytes.hex()
        }
        
        try:
            cmd_prefix = packet_bytes[:3]
            if cmd_prefix == b'ZWA':
                result['parsed_data'] = self.parse_comprehensive_data(packet_bytes)
            elif cmd_prefix == b'ZWB':
                result['parsed_data'] = self.parse_device_name(packet_bytes)
            elif cmd_prefix == b'ZWC':
                result['parsed_data'] = self.parse_version_info(packet_bytes)
            elif cmd_prefix == b'ZWN':
                result['parsed_data'] = self.parse_ap_warning(packet_bytes)
            elif cmd_prefix == b'ZWV':
                result['parsed_data'] = self.parse_page_display(packet_bytes)
            elif cmd_prefix == b'ZWP':
                result['parsed_data'] = self.parse_scrolling_setting(packet_bytes)
            elif cmd_prefix == b'ZWY':
                result['parsed_data'] = self.parse_language_setting(packet_bytes)
            elif cmd_prefix == b'ZWM':
                result['parsed_data'] = self.parse_system_status(packet_bytes)
        except Exception as e:
            result['parse_error'] = str(e)
        
        return result
    
    def parse_from_file(self, filename):
        """从文件读取并解析"""
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            packets = []
            for i in range(0, len(data), self.PACKET_SIZE):
                packet = data[i:i + self.PACKET_SIZE]
                if len(packet) == self.PACKET_SIZE:
                    packets.append(self.parse_packet(packet))
            
            return {
                'total_bytes': len(data),
                'packet_count': len(packets),
                'packets': packets
            }
        except FileNotFoundError:
            return {'error': f'File not found: {filename}'}
        except Exception as e:
            return {'error': str(e)}


# 主程序
def main():
    parser = LCDPacketParser()
    result = parser.parse_from_file('ik_lcd.log')
    
    if 'error' in result:
        print(f"错误: {result['error']}")
        return
    
    print(f"总字节数: {result['total_bytes']}")
    print(f"数据包数量: {result['packet_count']}\n")
    
    # 统计命令类型
    cmd_stats = {}
    checksum_errors = 0
    
    for packet in result['packets']:
        cmd = packet['command_type']
        cmd_stats[cmd] = cmd_stats.get(cmd, 0) + 1
        if not packet['checksum_valid']:
            checksum_errors += 1
    
    print("命令类型统计:")
    for cmd, count in sorted(cmd_stats.items()):
        print(f"  {cmd}: {count}")
    print(f"\n校验和错误数量: {checksum_errors}")
    
    # 显示前10个数据包
    print(f"\n{'='*80}")
    print("前10个数据包详情:")
    print(f"{'='*80}\n")
    
    for idx, packet in enumerate(result['packets'][:10], 1):
        print(f"{'='*80}")
        print(f"数据包 #{idx}")
        print(f"{'='*80}")
        print(f"命令头: {packet['command_header']}")
        print(f"命令字符串: {packet['command_string']}")
        print(f"命令类型: {packet['command_type']}")
        print(f"校验和验证: {'✓ 通过' if packet['checksum_valid'] else '✗ 失败'}")
        print(f"校验和信息: {packet['checksum_info']}")
        
        if 'parsed_data' in packet:
            print(f"\n解析数据:")
            for key, value in packet['parsed_data'].items():
                print(f"  {key}: {value}")
        
        if 'parse_error' in packet:
            print(f"\n解析错误: {packet['parse_error']}")
        
        print()
    
    # 保存完整结果到JSON
    with open('ik_lcd_parsed.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"完整解析结果已保存到: ik_lcd_parsed.json")


if __name__ == "__main__":
    main()