"""
proto.py - Fungsi bersama untuk KDC dan peer (Alice/Bob).

Format kawat (wire format): satu pesan = satu baris teks ASCII "TAG:payload\n"
  (notasi mengikuti PPT 'Key Distribution Scenario', || = concatenation)
  - Langkah 1 (Alice -> KDC)    : REQ:IDA||IDB||N1          (plaintext)
  - Langkah 2 (KDC -> Alice)    : RESP:<hexA>||<hexB>       E(Ka,[Ks||IDA||IDB||N1]) || E(Kb,[Ks||IDA])
  - Langkah 3 (Alice -> Bob)    : TICKET:<hexB>             E(Kb,[Ks||IDA])  (hexB diteruskan apa adanya)
  - Langkah 4 (Bob -> Alice)    : NONCE:<hex>               E(Ks, N2)
  - Langkah 5 (Alice -> Bob)    : NONCE_REPLY:<hex>         E(Ks, f(N2)),  f(N2) = N2 + 1
  - Konfirmasi                  : AUTH_OK: / AUTH_FAIL:alasan
  - Setelah itu (AES, Ks)       : MSG:<hex>                 E(Ks, pesan)
Karena ciphertext berupa teks HEX, mudah dibaca di Wireshark (Follow TCP Stream).
"""
import secrets
import string

SEP = "||"   # simbol || (concatenation) sesuai PPT
CHARSET = string.ascii_letters + string.digits
F_OFFSET = 1   # f(N2) = N2 + 1


def gen_session_key():
    """Session key Ks: 16 karakter ASCII acak (huruf+angka)."""
    return "".join(secrets.choice(CHARSET) for _ in range(16))


def gen_nonce():
    return secrets.randbelow(10**9)


def f(n):
    """Fungsi f(N2) pada langkah 5 (bebas, disepakati kedua pihak)."""
    return n + F_OFFSET


def send_line(sock, tag, payload=""):
    sock.sendall(f"{tag}:{payload}\n".encode("ascii"))


def recv_line(rfile):
    """Baca satu baris dari socket-file. Return (tag, payload)."""
    line = rfile.readline()
    if not line:
        raise ConnectionError("koneksi ditutup")
    line = line.rstrip("\r\n")
    tag, _, payload = line.partition(":")
    return tag, payload
