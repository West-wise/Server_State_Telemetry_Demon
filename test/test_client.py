import socket
import struct
import time
import hmac
import hashlib
import sys

# [설정]
HOST = '127.0.0.1'
PORT = 41924
MAGIC = 0x53535444
# 256-bit Secure Key (Matched with server config)
# config/sstd.ini의 hmac_key와 일치해야 함 (Hex Decoding 필요)
HEX_KEY = ""
SECRET_KEY = bytes.fromhex(HEX_KEY) # Hex 문자열을 바이트로 변환해야 함
FMT = '<IBBHHIQI16s' # Header Format

def run_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return
        
        print("[+] Connected! Sending Handshake...")

        # 1. Handshake Packet (CMD=1)
        req_id = 1
        payload = b"AUTH_ME"
        body_len = len(payload)
        
        # Header Creation
        timestamp = int(time.time() * 1000)
        temp_header = struct.pack(FMT, MAGIC, 1, 1, 0, 1, req_id, timestamp, body_len, b'\x00' * 16)
        full_data = temp_header + payload
        auth_tag = hmac.new(SECRET_KEY, full_data, hashlib.sha256).digest()[:16]
        
        real_header = struct.pack(FMT, MAGIC, 1, 1, 0, 1, req_id, timestamp, body_len, auth_tag)
        
        # [Debug] Header Dump
        print("[DEBUG] Sending Header:", real_header.hex(' '))
        
        s.sendall(real_header + payload)
        
        print("[*] Handshake sent. Waiting for stream...")

        # 2. Receive Loop (Push Model)
        while True:
            try:
                # 헤더 읽기 (42 bytes)
                header_data = s.recv(42)
                if not header_data or len(header_data) < 42:
                    print("[!] Server disconnected or invalid header.")
                    break
                
                # 헤더 파싱
                magic, ver, type_, cid, cmd, seq, ts, body_len, tag = struct.unpack(FMT, header_data)
                
                if magic != MAGIC:
                    print(f"[!] Invalid Magic: {hex(magic)}")
                    break
                    
                # 바디 읽기
                body_data = b''
                while len(body_data) < body_len:
                    chunk = s.recv(body_len - len(body_data))
                    if not chunk: break
                    body_data += chunk
                
                # HMAC 검증 (Optional here for test)
                
                # HMAC 검증 (Optional here for test)
                
                if cmd == 0x12: # RES_HostInfo (18)
                    # HostInfo 구조체: hostname(string), os_name(string), release_info(string)
                    # C++ 구조체는 std::string을 포함하고 있으므로 직렬화 방식에 따라 다름.
                    # 하지만 현재 Protocol.hpp 정의상 HostInfo는 가변 길이 문자열을 포함할 것으로 추정됨.
                    # 여기서는 단순히 문자열로 디코딩하여 출력.
                    try:
                        info_str = body_data.decode('utf-8', errors='replace')
                        print(f"\n[Host Info] {info_str}")
                    except Exception as e:
                        print(f"\n[!] Failed to parse HostInfo: {e}")

                elif cmd == 0x02: # RES_SystemStat (17)
                    # SystemStats 구조체: 
                    # uint16_t valid_mask;  // 2
                    # uint16_t reserved;    // 2
                    # uint8_t cpu_usage;    // 1
                    # uint8_t mem_usage;    // 1
                    # uint8_t disk_usage;   // 1
                    # uint8_t temp_cpu;     // 1
                    # netInfo net_rx_bytes; // 16 (4*4)
                    # netInfo net_tx_bytes; // 16 (4*4)
                    # uint16_t proc_count;  // 2
                    # uint16_t user_count;  // 2
                    # uint32_t uptime_secs; // 4
                    # Total: 48 bytes
                    
                    if len(body_data) >= 48:
                        st_fmt = '<HHBBBBIIIIIIIIHHI'
                        valid, res, cpu, mem, disk, temp, \
                        rx_bytes, rx_pkts, rx_errs, rx_drop, \
                        tx_bytes, tx_pkts, tx_errs, tx_drop, \
                        proc, user, uptime = struct.unpack(st_fmt, body_data[:48])
                        
                        # 화면 지우고 출력 (ANSI Escape Code)
                        # \033[2J: 화면 클리어, \033[H: 커서 홈 이동
                        sys.stdout.write("\033[2J\033[H")
                        print("="*40)
                        print(f" [ System Telemetry Client ]")
                        print("="*40)
                        print(f" CPU Usage  : {cpu:>3}%  | Temp: {temp}C")
                        print(f" MEM Usage  : {mem:>3}%")
                        print(f" Disk Usage : {disk:>3}%")
                        print(f" Uptime     : {uptime} sec")
                        print("-" * 40)
                        print(f" [ Network RX ]")
                        print(f" Bytes/s    : {rx_bytes}")
                        print(f" Packets/s  : {rx_pkts}")
                        print(f" Errors/s   : {rx_errs}")
                        print(f" Drops/s    : {rx_drop}")
                        print("-" * 40)
                        print(f" [ Network TX ]")
                        print(f" Bytes/s    : {tx_bytes}")
                        print(f" Packets/s  : {tx_pkts}")
                        print(f" Errors/s   : {tx_errs}")
                        print(f" Drops/s    : {tx_drop}")
                        print("-" * 40)
                        print(f" Processes  : {proc}")
                        print(f" Users      : {user}")
                        print("="*40)
                        sys.stdout.flush()
                    else:
                        print(f"[Stream] Received {len(body_data)} bytes (Body) - Expected 48 bytes")
                else:
                    print(f"[Stream] Unknown CMD: {cmd}")

            except KeyboardInterrupt:
                print("\n[*] Initializing disconnect...")
                break
            except Exception as e:
                print(f"\n[!] Error: {e}")
                break
    
    print("[*] Client stopped.")

if __name__ == "__main__":
    run_client()