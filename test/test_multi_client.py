import socket
import struct
import time
import hmac
import hashlib
import threading  # [MODIFY]

def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF

def siphash128(key: bytes, data: bytes) -> bytes:
    k0 = int.from_bytes(key[0:8], 'little')
    k1 = int.from_bytes(key[8:16], 'little')
    
    v0 = 0x736f6d6570736575 ^ k0
    v1 = 0x646f72616e646f6d ^ k1 ^ 0xee
    v2 = 0x6c7967656e657261 ^ k0
    v3 = 0x7465646279746573 ^ k1
    
    def sipround():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = rotl(v1, 13)
        v1 ^= v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = rotl(v1, 17)
        v1 ^= v2
        v2 = rotl(v2, 32)

    inlen = len(data)
    left = inlen % 8
    end = inlen - left
    b = (inlen << 56) & 0xFFFFFFFFFFFFFFFF
    
    for i in range(0, end, 8):
        mi = int.from_bytes(data[i:i+8], 'little')
        v3 ^= mi
        sipround(); sipround()
        v0 ^= mi
        
    t = 0
    if left > 0:
        t = int.from_bytes(data[end:], 'little')
    b |= t
    
    v3 ^= b
    sipround(); sipround()
    v0 ^= b
    
    v2 ^= 0xee
    sipround(); sipround(); sipround(); sipround()
    out0 = v0 ^ v1 ^ v2 ^ v3
    
    v1 ^= 0xdd
    sipround(); sipround(); sipround(); sipround()
    out1 = v0 ^ v1 ^ v2 ^ v3
    
    return out0.to_bytes(8, 'little') + out1.to_bytes(8, 'little')

HOST = '127.0.0.1'
PORT = 41924
MAGIC = 0x53535444
HEX_KEY = ""
SECRET_KEY = bytes.fromhex(HEX_KEY)
HEADER_FMT = '<IBBHIQI16s'  # 40 bytes (cmd_mask 제거됨)
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# [MODIFY] 정확히 n바이트 읽기
def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return b''
        data += chunk
    return data

# [MODIFY] 공유 카운터/상태
class SharedStats:
    def __init__(self, n: int):
        self.lock = threading.Lock()
        self.ok_cnt = [0] * n      # 정상 패킷 수신 횟수
        self.err_cnt = [0] * n     # 에러 횟수
        self.disc_cnt = [0] * n    # disconnect 횟수

def run_client_instance(idx: int, stop_event: threading.Event, shared: SharedStats):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except Exception:
            with shared.lock:
                shared.err_cnt[idx] += 1
            return

        # handshake
        req_id = 1
        payload = b"AUTH_ME"
        body_len = len(payload)
        timestamp = int(time.time() * 1000)
        
        # [수정 1] HEADER_FMT 변수명 통일
        temp_header = struct.pack(HEADER_FMT, 
                                MAGIC_NUMBER, 1, 1, 0, req_id, timestamp, body_len, b'\x00' * 16)
        
        full_data = temp_header + payload
        auth_tag = siphash128(SECRET_KEY, full_data) 
        
        real_header = struct.pack(HEADER_FMT, 
                                MAGIC_NUMBER, 1, 1, 0, req_id, timestamp, body_len, auth_tag)

        try:
            s.sendall(real_header + payload)
        except Exception:
            with shared.lock:
                shared.err_cnt[idx] += 1
            return

        while not stop_event.is_set():
            try:
                # [수정 2] 42 대신 HEADER_SIZE(40) 사용
                header_data = recv_exact(s, HEADER_SIZE)
                if not header_data:
                    with shared.lock:
                        shared.disc_cnt[idx] += 1
                    break

                # [수정 3] cmd 변수 제거 (9개 -> 8개)
                magic, ver, type_, cid, seq, ts, body_len, tag = struct.unpack(HEADER_FMT, header_data)
                if magic != MAGIC_NUMBER:
                    with shared.lock:
                        shared.err_cnt[idx] += 1
                    break

                body_data = recv_exact(s, body_len) if body_len > 0 else b''
                if body_len > 0 and not body_data:
                    with shared.lock:
                        shared.disc_cnt[idx] += 1
                    break

                # [MODIFY] 정상 수신 카운트만 증가 (출력 없음)
                with shared.lock:
                    shared.ok_cnt[idx] += 1

            except Exception:
                with shared.lock:
                    shared.err_cnt[idx] += 1
                break

def run_multi_clients(n_clients: int = 50, duration_sec: int = 30):
    stop_event = threading.Event()
    shared = SharedStats(n_clients)  # [MODIFY]

    threads = []
    for i in range(n_clients):
        t = threading.Thread(target=run_client_instance, args=(i, stop_event, shared), daemon=True)
        t.start()
        threads.append(t)

    # [MODIFY] 1초마다 요약 출력 (출력량 최소)
    start = time.time()
    try:
       while time.time() - start < duration_sec:
            time.sleep(1)

            with shared.lock:
                total_ok = sum(shared.ok_cnt)
                total_err = sum(shared.err_cnt)
                total_disc = sum(shared.disc_cnt)

            print(f"[SUMMARY] clients={n_clients} ok_packets={total_ok} err={total_err} disc={total_disc}")

            # [추가] GitHub Actions CI 자동화를 위해 에러 시 프로세스 실패(Exit 1) 처리
            if total_err > 0:
                print("[!] Test failed due to packet errors.")
                import sys
                sys.exit(1)

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2.0)

if __name__ == "__main__":
    run_multi_clients(n_clients=100, duration_sec=30)  # 예: 100클라 30초
