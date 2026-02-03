import socket
import struct
import time
import hmac
import hashlib

# [설정] 서버와 동일한 키여야 함
HOST = '127.0.0.1'
PORT = 41924
MAGIC = 0x53535444  # 'SSTD'
SECRET_KEY = b"sstd_tmp_secret_key_2026" # [주의] 서버 코드의 SECRET_KEY와 정확히 일치시킬 것!

def send_packet():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Connecting to {HOST}:{PORT}...")
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("[!] Connection failed. Is the server running?")
            return
        print("[+] Connected!")

        # 1. 데이터 준비
        version = 1
        msg_type = 1 # REQ_Connect
        client_id = 101     # [NEW] C++ struct의 client_id 대응
        cmd_mask = 100      # C++ struct의 cmd_mask 대응
        seq = 1             # request_id
        
        # [NEW] C++ struct의 timestamp 대응 (Unix Timestamp MS)
        timestamp = int(time.time() * 1000) 
        
        payload = b"Hello Server!"
        body_len = len(payload)
        
        # 2. 구조체 포맷 문자열 정의 (Little Endian, 1 byte alignment)
        # I:uint32, B:uint8, B:uint8, H:uint16, H:uint16, I:uint32, Q:uint64, I:uint32, 16s:char[16]
        # 총 크기: 4+1+1+2+2+4+8+4+16 = 42 bytes
        fmt = '<IBBHHIQI16s'

        # 3. HMAC 계산을 위해 Auth Tag를 0으로 채운 임시 헤더 생성
        zero_auth_tag = b'\x00' * 16
        
        # pack 순서: magic, version, type, client_id, cmd_mask, req_id, timestamp, body_len, auth_tag
        temp_header = struct.pack(fmt, 
                             MAGIC, version, msg_type, client_id, cmd_mask, seq, timestamp, body_len, zero_auth_tag)
        
        # 4. 전체 데이터(헤더+바디)에 대해 HMAC-SHA256 계산
        full_data = temp_header + payload
        # digest()의 앞 16바이트만 사용 (Truncated HMAC)
        calc_hmac = hmac.new(SECRET_KEY, full_data, hashlib.sha256).digest()[:16]
        
        # 5. 진짜 헤더 생성 (계산된 HMAC 포함)
        real_header = struct.pack(fmt, 
                             MAGIC, version, msg_type, client_id, cmd_mask, seq, timestamp, body_len, calc_hmac)
        
        # 6. 전송
        final_packet = real_header + payload
        print(f"[*] Sending Header({len(real_header)}) + Body({len(payload)}) = {len(final_packet)} bytes")
        s.sendall(final_packet)

        # 응답 대기
        try:
            # 헤더 크기(42) + 예상 바디 등 넉넉하게 수신
            response = s.recv(1024)
            if not response:
                print("[!] Server closed connection.")
            else:
                print(f"[<] Received: {len(response)}bytes")
                # 응답 헤더 파싱 (선택 사항)
                if len(response) >= 42:
                    r_magic, r_ver, r_type, r_cid, r_cmd, r_seq, r_ts, r_len, r_tag = struct.unpack(fmt, response[:42])
                    print(f"    -> Magic: {hex(r_magic)}, Cmd: {r_cmd}, BodyLen: {r_len}")
                    print(f"    -> Body: {response[42:]}")
        except Exception as e:
            print(f"[!] Error receiving: {e}")
            
        time.sleep(1)
        print("[*] Done.")

if __name__ == "__main__":
    send_packet()