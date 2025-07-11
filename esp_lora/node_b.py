import uos
import ubinascii
import ujson
import utime
from machine import SPI, Pin
from ecdsa import SigningKey, VerifyingKey, NIST256p
from hkdf import HKDF
from lora_config import LoRaConfig

LSK_FILE = 'LSK_B.key'
PK_FILE = 'PK_B.key'
PEER_PK_FILE = 'PK_A.key'
LOG_FILE = 'nodeB_log.json'
AUTH_FAIL_THRESHOLD = 3

def log_event(event):
    event['timestamp_human'] = utime.localtime()
    with open(LOG_FILE, "a") as f:
        f.write(ujson.dumps(event) + "\n")

def sha256(data):
    import uhashlib
    h = uhashlib.sha256()
    h.update(data)
    return h.digest()

def hkdf_sha256(shared, salt, info, length=16):
    hkdf = HKDF(shared, salt, info, length)
    return hkdf.derive()

def generate_or_load_keys(lsk_file, pk_file):
    try:
        with open(lsk_file, 'rb') as f:
            lsk_bytes = f.read()
        with open(pk_file, 'rb') as f:
            pk_bytes = f.read()
        lsk = SigningKey.from_string(lsk_bytes, curve=NIST256p)
        pk = VerifyingKey.from_string(pk_bytes, curve=NIST256p)
    except OSError:
        lsk = SigningKey.generate(curve=NIST256p)
        pk = lsk.get_verifying_key()
        with open(lsk_file, 'wb') as f:
            f.write(lsk.to_string())
        with open(pk_file, 'wb') as f:
            f.write(pk.to_string())
    return lsk, pk

def load_peer_pk(peer_pk_file):
    with open(peer_pk_file, 'rb') as f:
        pk_bytes = f.read()
    return VerifyingKey.from_string(pk_bytes, curve=NIST256p)

class IntrusionDetection:
    def __init__(self, threshold=AUTH_FAIL_THRESHOLD):
        self.failed_attempts = 0
        self.threshold = threshold
        self.blocked = False

    def log_auth_result(self, success):
        if not success:
            self.failed_attempts += 1
            log_event({"phase": "ids", "event": "auth_fail", "fail_count": self.failed_attempts})
            if self.failed_attempts >= self.threshold:
                self.blocked = True
                log_event({"phase": "ids", "event": "blocked"})
        else:
            if self.failed_attempts > 0:
                log_event({"phase": "ids", "event": "reset_fail_counter"})
            self.failed_attempts = 0
            self.blocked = False

    def is_blocked(self):
        return self.blocked

def secrets_token_bytes(n):
    return uos.urandom(n)

def main():
    spi = SPI(1, baudrate=10000000, polarity=0, phase=0)
    cs = Pin(18, Pin.OUT)
    reset = Pin(14, Pin.OUT)
    lora = LoRaConfig(spi, cs, reset)

    ids = IntrusionDetection()
    LSK_B, PK_B = generate_or_load_keys(LSK_FILE, PK_FILE)
    PK_A = load_peer_pk(PEER_PK_FILE)
    log_event({"phase": "init", "event": "keys_loaded"})

    session_start = utime.time()
    log_event({"phase": "init", "event": "session_start", "time": session_start})

    M_A = lora.receive(timeout=30000)
    if not M_A:
        log_event({"phase": "auth", "event": "wait_timeout_M_A"})
        print("Timeout waiting for M_A")
        return

    if ids.is_blocked():
        log_event({"phase": "auth", "event": "blocked_by_ids"})
        print("Authentication blocked due to IDS.")
        return

    N_A = M_A[:16]
    R_A_bytes = M_A[16:81]
    s_A = int.from_bytes(M_A[81:], "big")
    c_A = sha256(PK_A.to_string() + R_A_bytes + N_A + b"AUTH_REQ")
    c_A_int = int.from_bytes(c_A, "big") % NIST256p.order

    if R_A_bytes[0] != 0x04:
        raise ValueError("R_A not in uncompressed format")
    x = int.from_bytes(R_A_bytes[1:33], "big")
    y = int.from_bytes(R_A_bytes[33:65], "big")
    from ecdsa.ellipticcurve import Point
    R_A_point = Point(NIST256p.curve, x, y)
    PK_A_point = PK_A.pubkey.point
    lhs = NIST256p.generator * s_A
    rhs = R_A_point + PK_A_point * c_A_int
    auth_success = lhs == rhs

    log_event({"phase": "auth", "role": "verifier", "event": "proof_verified", "success": auth_success})
    ids.log_auth_result(auth_success)
    if ids.is_blocked():
        log_event({"phase": "auth", "event": "blocked_by_ids_after_verification"})
        print("Authentication blocked due to IDS after verification.")
        return
    if not auth_success:
        print("Authentication failed")
        return

    N_B = secrets_token_bytes(16)
    r_B = int.from_bytes(secrets_token_bytes(32), 'big') % NIST256p.order
    R_B_point = NIST256p.generator * r_B
    R_B_bytes = b'\x04' + R_B_point.x().to_bytes(32, "big") + R_B_point.y().to_bytes(32, "big")
    c_B = sha256(PK_B.to_string() + R_B_bytes + N_A + N_B + b"AUTH_RESP")
    c_B_int = int.from_bytes(c_B, "big") % NIST256p.order
    s_B = (r_B + c_B_int * int.from_bytes(LSK_B.to_string(), "big")) % NIST256p.order

    M_B = N_B + R_B_bytes + s_B.to_bytes(32, "big")
    log_event({"phase": "auth", "role": "prover", "event": "proof_generated", "packet_size": len(M_B)})

    lora.send(M_B)

    shared_secret_point = PK_A.pubkey.point * LSK_B.privkey.secret_multiplier
    shared_bytes = shared_secret_point.x().to_bytes(32, "big")
    session_key = hkdf_sha256(shared_bytes, N_A + N_B, b"LoRa-ZKP-Session", 16)
    log_event({"phase": "session", "event": "session_key_derived"})

    enc_msg = lora.receive(timeout=30000)
    if not enc_msg:
        log_event({"phase": "comm", "event": "wait_timeout_encA2B"})
        print("Timeout waiting for encA2B from Node A")
        return

    nonce = enc_msg[:13]
    ciphertext = enc_msg[13:]

    from ucryptolib import aes
    cipher = aes(session_key, 1)  # 1 = AES.MODE_CCM if available
    try:
        plaintext = cipher.decrypt(ciphertext)
        log_event({"phase": "comm", "event": "message_received", "plaintext_len": len(plaintext)})
    except Exception as e:
        log_event({"phase": "comm", "event": "decryption_failed", "error": str(e)})
        print("Decryption failed:", e)
        return

    session_end = utime.time()
    log_event({"phase": "session", "event": "session_end", "time": session_end,
               "session_duration_sec": session_end - session_start})
    print("Node B protocol completed successfully.")

if __name__ == "__main__":
    main()
