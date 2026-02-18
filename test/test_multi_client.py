import socket
import struct
import time
import hmac
import hashlib
import threading  # [MODIFY]

HOST = '127.0.0.1'
PORT = 41924
MAGIC = 0x53535444
HEX_KEY = ""
SECRET_KEY = bytes.fromhex(HEX_KEY)
FMT = '<IBBHHIQI16s'  # 42 bytes

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

        temp_header = struct.pack(FMT, MAGIC, 1, 1, 0, 1, req_id, timestamp, body_len, b'\x00' * 16)
        full_data = temp_header + payload
        auth_tag = hmac.new(SECRET_KEY, full_data, hashlib.sha256).digest()[:16]
        real_header = struct.pack(FMT, MAGIC, 1, 1, 0, 1, req_id, timestamp, body_len, auth_tag)

        try:
            s.sendall(real_header + payload)
        except Exception:
            with shared.lock:
                shared.err_cnt[idx] += 1
            return

        while not stop_event.is_set():
            try:
                header_data = recv_exact(s, 42)
                if not header_data:
                    with shared.lock:
                        shared.disc_cnt[idx] += 1
                    break

                magic, ver, type_, cid, cmd, seq, ts, body_len, tag = struct.unpack(FMT, header_data)
                if magic != MAGIC:
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

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2.0)

if __name__ == "__main__":
    run_multi_clients(n_clients=100, duration_sec=30)  # 예: 100클라 30초
