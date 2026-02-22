import socket
import struct
import time
import hmac
import hashlib
import sys
import os
import configparser
from dataclasses import dataclass
from typing import Optional

# [Protocol Constants]
MAGIC_NUMBER = 0x53535444
HMAC_TAG_SIZE = 16

# [Packet Structure Formats]
# SecureHeader:
#   magic(4) + version(1) + type(1) + client_id(2) +
#   cmd_mask(2) + req_id(4) + timestamp(8) + body_len(4) + auth_tag(16)
# Total: 42 bytes
HEADER_FMT = '<IBBHHIQI16s'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# SystemStats (64 bytes) matches C++ struct:
#   uint16_t valid_mask;  // 2
#   uint16_t reserved;    // 2
#   uint8_t cpu_usage;    // 1
#   uint8_t mem_usage;    // 1
#   uint8_t disk_usage;   // 1
#   uint8_t temp_cpu;     // 1
#
#   netInfo net_rx_bytes; // 16 (4*4)
#   netInfo net_tx_bytes; // 16 (4*4)
#
#   uint16_t proc_count;          // 2
#   uint16_t total_proc_count;    // 2
#   uint16_t net_user_count;      // 2
#   uint16_t connected_user_count;// 2
#   uint32_t uptime_secs;         // 4
#   fdInfo fd_info;               // 8 (2+2+4?) -> needs check
#   ... Actually let's check fdInfo definition again.
#   struct fdInfo {
#       uint16_t allocated_fd_cnt; // 2
#       uint16_t using_fd_cnt;     // 2
#       uint64_t max_limit_fd;     // 8  <-- WAIT, C++ said uint64_t.
#   };
#
#   Let's re-verify Protocol.hpp sizes.
#   netInfo: 4*4 = 16 bytes.
#   fdInfo: 2+2+8 = 12 bytes?
#   But SystemStats size is asserted as 64 bytes.
#
#   Let's check offsets in C++:
#   0: valid_mask(2)
#   2: reserved(2)
#   4: cpu(1)
#   5: mem(1)
#   6: disk(1)
#   7: temp(1)
#   8: net_rx(16) -> 24
#   24: net_tx(16) -> 40
#   40: proc_count(2)
#   42: total_proc_count(2)
#   44: net_user_count(2)
#   46: connected_user_count(2)
#   48: uptime_secs(4) -> 52
#   52: fd_info(??)
#
#   If fd_info is 12 bytes (2+2+8), then 52+12 = 64. Matches!
#
#   So Python fmt:
#   H H B B B B (4s) (16s) (16s) H H H H I H H Q
#   Wait, netInfo is 4 uint32_t.
#   So:
#   H (valid)
#   H (reserved)
#   B (cpu)
#   B (mem)
#   B (disk)
#   B (temp)
#   4I (net_rx)
#   4I (net_tx)
#   H (proc)
#   H (total_proc)
#   H (net_user)
#   H (conn_user)
#   I (uptime)
#   H (fd_alloc)
#   H (fd_using)
#   Q (fd_max)
#
STATS_FMT = '<HHBBQIIIQIIIIIHHIIIQQQQQQQQ'
STATS_SIZE = struct.calcsize(STATS_FMT)

assert STATS_SIZE == 134, f"Stats size mismatch: {STATS_SIZE} != 134"

class SSTDClient:
    def __init__(self, config_path='../config/sstd.ini'):
        self.config = configparser.ConfigParser()
        if not os.path.exists(config_path):
             # Try relative to script location
             base_dir = os.path.dirname(os.path.abspath(__file__))
             config_path = os.path.join(base_dir, '..', 'config', 'sstd.ini')
             
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
            
        self.config.read(config_path)
        
        self.host = '127.0.0.1' 
        self.port = self.config.getint('server', 'port', fallback=41924)
        
        # Load and verify HMAC key
        hex_key = self.config.get('security', 'hmac_key', fallback='').strip('"').strip("'")
        if not hex_key:
            raise ValueError("HMAC key not found in config")
            
        self.secret_key = bytes.fromhex(hex_key)
        self.sock: Optional[socket.socket] = None

    def connect(self):
        print(f"[*] Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print("[+] Connected!")

    def send_handshake(self):
        req_id = 1
        payload = b"AUTH_ME"
        body_len = len(payload)
        timestamp = int(time.time() * 1000)
        
        # 16 bytes padding/tag placeholder
        temp_header = struct.pack(HEADER_FMT, 
                                MAGIC_NUMBER, 1, 1, 0, 1, req_id, timestamp, body_len, b'\x00' * 16)
        
        full_data = temp_header + payload
        auth_tag = hmac.new(self.secret_key, full_data, hashlib.sha256).digest()[:16]
        
        real_header = struct.pack(HEADER_FMT, 
                                MAGIC_NUMBER, 1, 1, 0, 1, req_id, timestamp, body_len, auth_tag)
                                
        self.sock.sendall(real_header + payload)
        print("[*] Handshake sent.")

    def run(self):
        try:
            self.connect()
            self.send_handshake()
            
            while True:
                header_data = self.read_bytes(HEADER_SIZE)
                if not header_data:
                    break
                    
                magic, ver, type_, cid, mask, seq, ts, body_len, tag = struct.unpack(HEADER_FMT, header_data)
                
                if magic != MAGIC_NUMBER:
                    print(f"[!] Invalid Magic: {hex(magic)}")
                    break

                body_data = self.read_bytes(body_len)
                
                # Check message type
                # 0x12 = RES_HostInfo
                # 0x11 = RES_SystemStat (Protocol.hpp says 0x11, but client code had 0x02? 
                # Let's check Protocol.hpp again.
                # MessageType::RES_SystemStat = 0x11
                # MessageType::RES_HostInfo = 0x12
                # The old client code had 0x02 for Stats. I should trust Protocol.hpp -> 0x11.
                
                if type_ == 0x12:
                    self.handle_host_info(body_data)
                elif type_ == 0x11:
                    self.handle_system_stats(body_data)
                else:
                    print(f"[!] Unknown Message Type: {hex(type_)}")

        except KeyboardInterrupt:
            print("\n[*] Stopping...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            if self.sock:
                self.sock.close()

    def read_bytes(self, size):
        data = b''
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def handle_host_info(self, data):
        try:
            # C++ sends serialized strings. 
            # If it's just raw bytes, we can try decoding. 
            # But usually C++ serialization implies length-prefixed equivalents or null-terminated?
            # Protocol.hpp: HostInfo { string, string, string }
            # If standard serialization is used, it often is: [len][chars][len][chars]...
            # For now, let's assume it might be printable text or we debug it.
            # The old client used `decode('utf-8', errors='replace')`.
            info = data.decode('utf-8', errors='replace')
            print(f"\n[Host Info] {info}")
        except Exception as e:
            print(f"[!] Host Info Parse Error: {e}")

    def handle_system_stats(self, data):
        if len(data) != STATS_SIZE:
            print(f"[!] Stat Body Size Mismatch: {len(data)} != {STATS_SIZE}")
            return

        unpacked = struct.unpack(STATS_FMT, data)
        
        # Valid Mask
        valid_mask = unpacked[0]
        
        # Basic Stats
        cpu = unpacked[2]
        mem = unpacked[3]
        
        # Network (RX)
        rx_bps = unpacked[4]
        rx_pps = unpacked[5]
        rx_eps = unpacked[6]
        rx_dps = unpacked[7]
        
        # Network (TX)
        tx_bps = unpacked[8]
        tx_pps = unpacked[9]
        tx_eps = unpacked[10]
        tx_dps = unpacked[11]
        
        # Counts
        proc_cnt = unpacked[12]
        total_proc = unpacked[13]
        net_users = unpacked[14]
        conn_users = unpacked[15]
        
        uptime = unpacked[16]
        
        # FD Info
        fd_alloc = unpacked[17]
        fd_using = unpacked[18]
        
        # Disk Summary (GB conversion for display)
        gb = 1024 * 1024 * 1024
        
        root_total, root_used = unpacked[19] / gb, unpacked[20] / gb
        home_total, home_used = unpacked[21] / gb, unpacked[22] / gb
        var_total, var_used = unpacked[23] / gb, unpacked[24] / gb
        boot_total, boot_used = unpacked[25] / gb, unpacked[26] / gb

        # Clear Screen
        if os.name == 'nt':
            os.system('cls')
        else:
            sys.stdout.write("\033[2J\033[H")
        
        print(f"========== System Telemetry (ID: {valid_mask:04x}) ==========")
        print(f" Uptime: {uptime}s")
        print(f" CPU: {cpu}% | MEM: {mem}%")
        print(f"-"*50)
        print(f" [Network]    RX          TX")
        print(f" Bytes/s      {rx_bps:<10}  {tx_bps:<10}")
        print(f" Pkts/s       {rx_pps:<10}  {tx_pps:<10}")
        print(f" Errors/s     {rx_eps:<10}  {tx_eps:<10}")
        print(f" Drops/s      {rx_dps:<10}  {tx_dps:<10}")
        print(f"-"*50)
        print(f" [Disk Usage] (GB)")
        print(f" /      : {root_used:.1f} / {root_total:.1f} GB")
        print(f" /home  : {home_used:.1f} / {home_total:.1f} GB")
        print(f" /var   : {var_used:.1f} / {var_total:.1f} GB")
        print(f" /boot  : {boot_used:.1f} / {boot_total:.1f} GB")
        print(f"-"*50)
        print(f" Processes: {proc_cnt}/{total_proc}")
        print(f" Users: {net_users} (Active), {conn_users} (Connected)")
        print(f" FDs: {fd_using}/{fd_alloc}")
        print(f"====================================================")
        sys.stdout.flush()

if __name__ == '__main__':
    client = SSTDClient()
    client.run()