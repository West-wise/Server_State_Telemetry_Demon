import socket
import struct
import time
import threading
import hashlib
import os
import sys
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─── Noise_XX (test_client.py와 동일 구현) ────────────────────────────────────
PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2b"
KEY_SIZE = 32

def _blake2b(data: bytes, key: bytes = None) -> bytes:
    if key:
        return hashlib.blake2b(data, key=key, digest_size=32).digest()
    return hashlib.blake2b(data, digest_size=32).digest()

def _mix_hash(h, data): return _blake2b(h + data)

def _mix_key(ck, dh):
    temp   = _blake2b(dh, key=ck)
    new_ck = _blake2b(bytes([0x01]), key=temp)
    new_k  = _blake2b(new_ck + bytes([0x02]), key=temp)
    return new_ck, new_k

def _build_nonce(n): return b'\x00' * 4 + n.to_bytes(8, 'little')

def _enc_hash(h, k, n, pt):
    ct = ChaCha20Poly1305(k).encrypt(_build_nonce(n), pt, h)
    return ct, _mix_hash(h, ct), n + 1

def _dec_hash(h, k, n, ct):
    pt = ChaCha20Poly1305(k).decrypt(_build_nonce(n), ct, h)
    return pt, _mix_hash(h, ct), n + 1

def _split(ck, is_initiator):
    temp = _blake2b(b'', key=ck)
    k1   = _blake2b(bytes([0x01]), key=temp)
    k2   = _blake2b(k1 + bytes([0x02]), key=temp)
    return (k1, k2) if is_initiator else (k2, k1)

def _recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk: raise ConnectionError("closed")
        data += chunk
    return data

def noise_xx_handshake(sock, server_pub: bytes) -> Tuple[bytes, bytes]:
    h = _blake2b(PROTOCOL_NAME); ck = h; k = bytes(KEY_SIZE); n = 0

    # msg1
    e_priv = X25519PrivateKey.generate()
    e_pub  = e_priv.public_key().public_bytes_raw()
    h = _mix_hash(h, e_pub)
    sock.sendall(e_pub)

    # msg2
    msg2 = _recv_exact(sock, KEY_SIZE * 2 + 16)
    se_pub = msg2[:KEY_SIZE]; enc_s = msg2[KEY_SIZE:]
    h = _mix_hash(h, se_pub)
    se_key = X25519PublicKey.from_public_bytes(se_pub)
    ck, k = _mix_key(ck, e_priv.exchange(se_key)); n = 0
    s_recv, h, n = _dec_hash(h, k, n, enc_s)
    if s_recv != server_pub: raise ValueError("Server pubkey mismatch")
    ck, k = _mix_key(ck, e_priv.exchange(X25519PublicKey.from_public_bytes(s_recv))); n = 0

    # msg3
    c_priv = X25519PrivateKey.generate()
    c_pub  = c_priv.public_key().public_bytes_raw()
    enc_c, h, n = _enc_hash(h, k, n, c_pub)
    ck, k = _mix_key(ck, c_priv.exchange(se_key))
    sock.sendall(enc_c)

    return _split(ck, True)

def send_noise(sock, key, nonce_ref, pt):
    ct = ChaCha20Poly1305(key).encrypt(_build_nonce(nonce_ref[0]), pt, None)
    nonce_ref[0] += 1
    sock.sendall(len(ct).to_bytes(4, 'little') + ct)

def recv_noise(sock, key, nonce_ref) -> bytes:
    ct_len = int.from_bytes(_recv_exact(sock, 4), 'little')
    ct = _recv_exact(sock, ct_len)
    pt = ChaCha20Poly1305(key).decrypt(_build_nonce(nonce_ref[0]), ct, None)
    nonce_ref[0] += 1
    return pt

# ─── 프로토콜 상수 ────────────────────────────────────────────────────────────
HOST         = os.environ.get('SSTD_HOST', '127.0.0.1')
PORT         = int(os.environ.get('SSTD_PORT', '41924'))
MAGIC_NUMBER = 0x53535444
HEADER_FMT   = '<IBBHIQI'   # 24 bytes, auth_tag 없음
HEADER_SIZE  = struct.calcsize(HEADER_FMT)
assert HEADER_SIZE == 24

def load_server_pubkey() -> bytes:
    paths = [
        os.environ.get('SSTD_KEY_PATH', ''),
        'sstd.key', '../sstd.key',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sstd.key'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build', 'sstd.key'),
    ]
    for p in paths:
        if p and os.path.exists(p):
            with open(p, 'rb') as f:
                raw = f.read(32)
            if len(raw) == 32:
                return X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes_raw()
    raise FileNotFoundError("sstd.key not found")

# ─── 멀티 클라이언트 ──────────────────────────────────────────────────────────
class SharedStats:
    def __init__(self, n):
        self.lock     = threading.Lock()
        self.ok_cnt   = [0] * n
        self.err_cnt  = [0] * n
        self.disc_cnt = [0] * n

def run_client_instance(idx, stop_event, shared, server_pub):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            send_key, recv_key = noise_xx_handshake(s, server_pub)
        except Exception as e:
            with shared.lock: shared.err_cnt[idx] += 1
            return

        send_nonce = [0]; recv_nonce = [0]

        # 핸드셰이크 패킷 전송
        try:
            payload   = b"AUTH_ME"
            timestamp = int(time.time() * 1000)
            header = struct.pack(HEADER_FMT, MAGIC_NUMBER, 1, 0x01, 0,
                                 1, timestamp, len(payload))
            send_noise(s, send_key, send_nonce, header + payload)
        except Exception:
            with shared.lock: shared.err_cnt[idx] += 1
            return

        while not stop_event.is_set():
            try:
                pt = recv_noise(s, recv_key, recv_nonce)
                if len(pt) < HEADER_SIZE:
                    with shared.lock: shared.disc_cnt[idx] += 1
                    break
                magic = struct.unpack_from('<I', pt)[0]
                if magic != MAGIC_NUMBER:
                    with shared.lock: shared.err_cnt[idx] += 1
                    break
                with shared.lock: shared.ok_cnt[idx] += 1
            except Exception:
                with shared.lock: shared.err_cnt[idx] += 1
                break

def run_multi_clients(n_clients=50, duration_sec=30):
    try:
        server_pub = load_server_pubkey()
    except Exception as e:
        print(f"[!] {e}")
        sys.exit(1)

    stop_event = threading.Event()
    shared     = SharedStats(n_clients)

    threads = []
    for i in range(n_clients):
        t = threading.Thread(target=run_client_instance,
                             args=(i, stop_event, shared, server_pub), daemon=True)
        t.start()
        threads.append(t)

    start = time.time()
    try:
        while time.time() - start < duration_sec:
            time.sleep(1)
            with shared.lock:
                ok   = sum(shared.ok_cnt)
                err  = sum(shared.err_cnt)
                disc = sum(shared.disc_cnt)
            print(f"[SUMMARY] clients={n_clients} ok={ok} err={err} disc={disc}")
            if err > 0:
                print("[!] Test failed: packet errors detected")
                sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads: t.join(timeout=2.0)

if __name__ == "__main__":
    run_multi_clients(n_clients=100, duration_sec=30)