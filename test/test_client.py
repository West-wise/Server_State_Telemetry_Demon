import socket
import struct
import time
import sys
import os
import hashlib
import configparser
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─── Noise_XX 구현 ─────────────────────────────────────────────────────────────
PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2b"
KEY_SIZE = 32
MAC_SIZE = 16

def _blake2b(data: bytes, key: bytes = None) -> bytes:
    if key:
        return hashlib.blake2b(data, key=key, digest_size=32).digest()
    return hashlib.blake2b(data, digest_size=32).digest()

def _mix_hash(h: bytes, data: bytes) -> bytes:
    return _blake2b(h + data)

def _mix_key(ck: bytes, dh: bytes) -> Tuple[bytes, bytes]:
    temp = _blake2b(dh, key=ck)
    new_ck = _blake2b(bytes([0x01]), key=temp)
    new_k  = _blake2b(new_ck + bytes([0x02]), key=temp)
    return new_ck, new_k

def _build_nonce(n: int) -> bytes:
    return b'\x00' * 4 + n.to_bytes(8, 'little')

def _encrypt_and_hash(h, k, n, pt):
    nonce = _build_nonce(n)
    ct = ChaCha20Poly1305(k).encrypt(nonce, pt, h)  # ad = h
    return ct, _mix_hash(h, ct), n + 1

def _decrypt_and_hash(h, k, n, ct):
    nonce = _build_nonce(n)
    pt = ChaCha20Poly1305(k).decrypt(nonce, ct, h)  # ad = h
    return pt, _mix_hash(h, ct), n + 1

def _split(ck: bytes, is_initiator: bool) -> Tuple[bytes, bytes]:
    temp = _blake2b(b'', key=ck)
    k1 = _blake2b(bytes([0x01]), key=temp)
    k2 = _blake2b(k1 + bytes([0x02]), key=temp)
    return (k1, k2) if is_initiator else (k2, k1)

def noise_xx_client_handshake(sock, server_pub: bytes) -> Tuple[bytes, bytes]:
    """
    Noise_XX initiator (client) handshake.
    Returns (send_key, recv_key).
    """
    h  = _blake2b(PROTOCOL_NAME)  # len=34 > 32 → hash
    ck = h
    k  = bytes(KEY_SIZE)
    n  = 0

    # ── Message 1: send e ──────────────────────────────────────────────────
    e_priv = X25519PrivateKey.generate()
    e_pub  = e_priv.public_key().public_bytes_raw()
    h = _mix_hash(h, e_pub)
    sock.sendall(e_pub)

    # ── Message 2: recv e, ee, s, es ───────────────────────────────────────
    msg2   = _recv_exact(sock, KEY_SIZE + KEY_SIZE + MAC_SIZE)  # 80 bytes
    se_pub     = msg2[:KEY_SIZE]
    encrypted_s = msg2[KEY_SIZE:]

    h = _mix_hash(h, se_pub)

    se_pub_key = X25519PublicKey.from_public_bytes(se_pub)

    # ee = DH(e_priv, se_pub)
    dh_ee = e_priv.exchange(se_pub_key)
    ck, k = _mix_key(ck, dh_ee)
    n = 0

    # Decrypt server static pubkey
    s_pub_recv, h, n = _decrypt_and_hash(h, k, n, encrypted_s)

    # ★ 서버 pubkey 검증 (QR에서 읽은 값과 비교)
    if s_pub_recv != server_pub:
        raise ValueError(f"[!] Server pubkey mismatch! MITM 가능성")

    # es = DH(e_priv, s_pub_recv)
    s_pub_key = X25519PublicKey.from_public_bytes(s_pub_recv)
    dh_es = e_priv.exchange(s_pub_key)
    ck, k = _mix_key(ck, dh_es)
    n = 0

    # ── Message 3: send s, se ──────────────────────────────────────────────
    c_priv = X25519PrivateKey.generate()  # 세션별 임시 static
    c_pub  = c_priv.public_key().public_bytes_raw()

    encrypted_c, h, n = _encrypt_and_hash(h, k, n, c_pub)

    # se = DH(c_priv, se_pub)
    dh_se = c_priv.exchange(se_pub_key)
    ck, k = _mix_key(ck, dh_se)

    sock.sendall(encrypted_c)

    send_key, recv_key = _split(ck, is_initiator=True)
    return send_key, recv_key

# ─── 전송 헬퍼 ────────────────────────────────────────────────────────────────
def _recv_exact(sock, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data

def send_noise(sock, send_key: bytes, send_nonce: list, plaintext: bytes):
    """4-byte LE 길이 + Noise 암호화 전송"""
    nonce = _build_nonce(send_nonce[0])
    ct = ChaCha20Poly1305(send_key).encrypt(nonce, plaintext, None)
    send_nonce[0] += 1
    sock.sendall(len(ct).to_bytes(4, 'little') + ct)

def recv_noise(sock, recv_key: bytes, recv_nonce: list) -> bytes:
    """4-byte 길이 수신 후 Noise 복호화"""
    ct_len = int.from_bytes(_recv_exact(sock, 4), 'little')
    ct = _recv_exact(sock, ct_len)
    nonce = _build_nonce(recv_nonce[0])
    pt = ChaCha20Poly1305(recv_key).decrypt(nonce, ct, None)
    recv_nonce[0] += 1
    return pt

# ─── 프로토콜 상수 ────────────────────────────────────────────────────────────
MAGIC_NUMBER = 0x53535444

# SecureHeader: magic(4)+version(1)+type(1)+client_id(2)+request_id(4)+timestamp(8)+body_len(4)
# auth_tag 제거됨
HEADER_FMT  = '<IBBHIQI'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
assert HEADER_SIZE == 24, f"Header size mismatch: {HEADER_SIZE}"

STATS_FMT  = '<HHBBQIIIQIIIIIHHIIIQQQQQQQQ'
STATS_SIZE = struct.calcsize(STATS_FMT)
assert STATS_SIZE == 134, f"Stats size mismatch: {STATS_SIZE}"

# ─── 클라이언트 ───────────────────────────────────────────────────────────────
class SSTDClient:
    def __init__(self, config_path='../config/sstd.ini'):
        self.config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, '..', 'config', 'sstd.ini')
        if os.path.exists(config_path):
            self.config.read(config_path, encoding='utf-8')

        self.host = os.environ.get('SSTD_HOST', '127.0.0.1')
        env_port = os.environ.get('SSTD_PORT')
        if env_port:
            self.port = int(env_port)
        else:
            try:
                self.port = int(self.config.get('server', 'port', fallback='41924').strip() or '41924')
            except Exception:
                self.port = 41924

        # 서버 pubkey 로드 (sstd.key → 32바이트 binary → pubkey 유도)
        self.server_pub = self._load_server_pubkey()

        self.sock: Optional[socket.socket] = None
        self.send_key: Optional[bytes] = None
        self.recv_key: Optional[bytes] = None
        self.send_nonce = [0]
        self.recv_nonce = [0]

    def _load_server_pubkey(self) -> bytes:
        """sstd.key(32바이트 private key) 읽어서 X25519 pubkey 유도"""
        search_paths = [
            os.environ.get('SSTD_KEY_PATH', ''),
            'sstd.key',
            '../sstd.key',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sstd.key'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build', 'sstd.key'),
        ]
        for path in search_paths:
            if path and os.path.exists(path):
                with open(path, 'rb') as f:
                    priv_bytes = f.read(32)
                if len(priv_bytes) == 32:
                    priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
                    pub = priv_key.public_key().public_bytes_raw()
                    print(f"[*] Server pubkey loaded: {pub.hex()}")
                    return pub
        raise FileNotFoundError("sstd.key not found (server public key required)")

    def connect(self):
        print(f"[*] Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        print("[*] Performing Noise_XX handshake...")
        self.send_key, self.recv_key = noise_xx_client_handshake(self.sock, self.server_pub)
        print("[+] Noise_XX handshake complete. Encrypted channel established.")

    def send_handshake(self):
        req_id    = 1
        payload   = b"AUTH_ME"
        timestamp = int(time.time() * 1000)
        header = struct.pack(HEADER_FMT,
                             MAGIC_NUMBER, 1, 0x01, 0,
                             req_id, timestamp, len(payload))
        send_noise(self.sock, self.send_key, self.send_nonce, header + payload)
        print("[*] Handshake sent.")

    def run(self):
        try:
            self.connect()
            self.send_handshake()

            while True:
                plaintext = recv_noise(self.sock, self.recv_key, self.recv_nonce)
                if len(plaintext) < HEADER_SIZE:
                    print("[!] Packet too small")
                    break

                magic, ver, type_, cid, seq, ts, body_len = struct.unpack(
                    HEADER_FMT, plaintext[:HEADER_SIZE])

                if magic != MAGIC_NUMBER:
                    print(f"[!] Invalid magic: {hex(magic)}")
                    break

                body = plaintext[HEADER_SIZE:HEADER_SIZE + body_len]

                if type_ == 0x11:
                    self.handle_system_stats(body)
                else:
                    print(f"[!] Unknown type: {hex(type_)}")

        except KeyboardInterrupt:
            print("\n[*] Stopping...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            if self.sock:
                self.sock.close()

    def handle_system_stats(self, data):
        if len(data) != STATS_SIZE:
            print(f"[!] Stats size mismatch: {len(data)} != {STATS_SIZE}")
            return

        unpacked = struct.unpack(STATS_FMT, data)
        valid_mask = unpacked[0]
        cpu, mem   = unpacked[2], unpacked[3]
        rx_bps, rx_pps, rx_eps, rx_dps = unpacked[4:8]
        tx_bps, tx_pps, tx_eps, tx_dps = unpacked[8:12]
        proc_cnt, total_proc = unpacked[12], unpacked[13]
        net_users, conn_users = unpacked[14], unpacked[15]
        uptime = unpacked[16]
        fd_alloc, fd_using = unpacked[17], unpacked[18]
        gb = 1024 ** 3
        root_total, root_used = unpacked[19] / gb, unpacked[20] / gb
        home_total, home_used = unpacked[21] / gb, unpacked[22] / gb
        var_total,  var_used  = unpacked[23] / gb, unpacked[24] / gb
        boot_total, boot_used = unpacked[25] / gb, unpacked[26] / gb

        if os.name == 'nt':
            os.system('cls')
        else:
            sys.stdout.write("\033[2J\033[H")

        print(f"========== System Telemetry (ID: {valid_mask:04x}) ==========")
        print(f" Uptime: {uptime}s")
        print(f" CPU: {cpu}% | MEM: {mem}%")
        print("-" * 50)
        print(f" [Network]    RX          TX")
        print(f" Bytes/s      {rx_bps:<10}  {tx_bps:<10}")
        print(f" Pkts/s       {rx_pps:<10}  {tx_pps:<10}")
        print(f" Errors/s     {rx_eps:<10}  {tx_eps:<10}")
        print(f" Drops/s      {rx_dps:<10}  {tx_dps:<10}")
        print("-" * 50)
        print(f" [Disk] (GB)")
        print(f" /     : {root_used:.1f}/{root_total:.1f}")
        print(f" /home : {home_used:.1f}/{home_total:.1f}")
        print(f" /var  : {var_used:.1f}/{var_total:.1f}")
        print(f" /boot : {boot_used:.1f}/{boot_total:.1f}")
        print("-" * 50)
        print(f" Processes: {proc_cnt}/{total_proc}")
        print(f" Users: {net_users} (net) {conn_users} (conn)")
        print(f" FDs: {fd_using}/{fd_alloc}")
        print("=" * 50)
        sys.stdout.flush()

if __name__ == '__main__':
    client = SSTDClient()
    client.run()