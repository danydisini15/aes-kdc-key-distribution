"""
aes.py - Implementasi AES-128 MANUAL (tanpa library kripto).

Isi:
  - Aritmatika GF(2^8)  : xtime, gmul
  - S-Box               : dihitung dari invers perkalian GF(2^8) + transformasi affine
  - Key Expansion       : 16 byte key -> 11 round key
  - SubBytes, ShiftRows, MixColumns, AddRoundKey (+ kebalikannya untuk dekripsi)
  - Mode ECB dan CBC, padding PKCS#7
  - Key & plaintext = ASCII, ciphertext = HEX

Pemakaian CLI (untuk uji / verifikasi):
  python aes.py selftest
  python aes.py enc  <key16> <plaintext> [ecb|cbc]
  python aes.py dec  <key16> <hex>       [ecb|cbc]
  python aes.py trace <key16> <plaintext_max16>   # tampilkan state tiap ronde
"""
import os
import sys

NB = 4          # jumlah kolom state
NK = 4          # jumlah word kunci (AES-128)
NR = 10         # jumlah ronde (AES-128)
BLOCK = 16      # ukuran blok (byte)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------------------------------------------------------------- GF(2^8)
def xtime(a):
    """Kalikan dengan x (=0x02) di GF(2^8), polinomial x^8+x^4+x^3+x+1 (0x11B)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def gmul(a, b):
    """Perkalian dua byte di GF(2^8) (shift-and-add)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    # 1) invers perkalian tiap byte di GF(2^8) (0 dipetakan ke 0)
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if gmul(a, b) == 1:
                inv[a] = b
                break
    # 2) transformasi affine
    sbox = [0] * 256
    for a in range(256):
        b = inv[a]
        sbox[a] = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
M = {n: [gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


# ------------------------------------------------- transformasi per ronde
# State = list 16 byte, urutan kolom (state[r + 4*c]), sama dengan urutan byte blok.
def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # baris r digeser ke kiri sebanyak r
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(s):
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out += [
            M[2][a[0]] ^ M[3][a[1]] ^ a[2] ^ a[3],
            a[0] ^ M[2][a[1]] ^ M[3][a[2]] ^ a[3],
            a[0] ^ a[1] ^ M[2][a[2]] ^ M[3][a[3]],
            M[3][a[0]] ^ a[1] ^ a[2] ^ M[2][a[3]],
        ]
    return out


def inv_mix_columns(s):
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out += [
            M[14][a[0]] ^ M[11][a[1]] ^ M[13][a[2]] ^ M[9][a[3]],
            M[9][a[0]] ^ M[14][a[1]] ^ M[11][a[2]] ^ M[13][a[3]],
            M[13][a[0]] ^ M[9][a[1]] ^ M[14][a[2]] ^ M[11][a[3]],
            M[11][a[0]] ^ M[13][a[1]] ^ M[9][a[2]] ^ M[14][a[3]],
        ]
    return out


def add_round_key(s, rk):
    return [x ^ k for x, k in zip(s, rk)]


# ------------------------------------------------------------ key schedule
def expand_key(key16):
    """16 byte key -> list 11 round key (masing-masing 16 byte)."""
    w = [list(key16[4 * i:4 * i + 4]) for i in range(NK)]
    for i in range(NK, NB * (NR + 1)):
        t = w[i - 1][:]
        if i % NK == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // NK - 1]              # Rcon
        w.append([w[i - NK][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(NR + 1)]


# ------------------------------------------------------------- satu blok
def _hx(s):
    return bytes(s).hex()


def encrypt_block(block, round_keys, trace=False):
    s = add_round_key(list(block), round_keys[0])
    if trace:
        print(f"  ronde 0  AddRoundKey : {_hx(s)}")
    for r in range(1, NR):
        s = sub_bytes(s)
        if trace: print(f"  ronde {r}  SubBytes    : {_hx(s)}")
        s = shift_rows(s)
        if trace: print(f"           ShiftRows   : {_hx(s)}")
        s = mix_columns(s)
        if trace: print(f"           MixColumns  : {_hx(s)}")
        s = add_round_key(s, round_keys[r])
        if trace: print(f"           AddRoundKey : {_hx(s)}")
    s = sub_bytes(s)
    if trace: print(f"  ronde {NR} SubBytes    : {_hx(s)}")
    s = shift_rows(s)
    if trace: print(f"           ShiftRows   : {_hx(s)}")
    s = add_round_key(s, round_keys[NR])
    if trace: print(f"           AddRoundKey : {_hx(s)}  <- ciphertext")
    return bytes(s)


def decrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[NR])
    for r in range(NR - 1, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, round_keys[r])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, round_keys[0])
    return bytes(s)


# ----------------------------------------------------- padding & mode operasi
def pkcs7_pad(data):
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK:
        raise ValueError("panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah / data rusak)")
    return data[:-n]


def validate_key(key):
    """Key harus ASCII dan tepat 16 karakter (AES-128)."""
    if not isinstance(key, str):
        raise ValueError("key harus string")
    try:
        kb = key.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("key harus ASCII")
    if len(kb) != 16:
        raise ValueError(f"key harus tepat 16 karakter ASCII (sekarang {len(kb)})")
    return kb


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_bytes(data, key_bytes, mode="cbc", iv=None):
    rk = expand_key(key_bytes)
    data = pkcs7_pad(data)
    blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    if mode == "ecb":
        return b"".join(encrypt_block(b, rk) for b in blocks)
    # CBC: IV acak di depan ciphertext
    iv = iv if iv is not None else os.urandom(BLOCK)
    out, prev = [iv], iv
    for b in blocks:
        prev = encrypt_block(_xor(b, prev), rk)
        out.append(prev)
    return b"".join(out)


def decrypt_bytes(data, key_bytes, mode="cbc"):
    rk = expand_key(key_bytes)
    if len(data) % BLOCK or not data:
        raise ValueError("panjang ciphertext bukan kelipatan 16 byte")
    if mode == "ecb":
        plain = b"".join(decrypt_block(data[i:i + BLOCK], rk) for i in range(0, len(data), BLOCK))
        return pkcs7_unpad(plain)
    prev, out = data[:BLOCK], []
    for i in range(BLOCK, len(data), BLOCK):
        blk = data[i:i + BLOCK]
        out.append(_xor(decrypt_block(blk, rk), prev))
        prev = blk
    return pkcs7_unpad(b"".join(out))


# --------------------------------------------- API teks: ASCII <-> HEX
def encrypt(plaintext, key, mode="cbc"):
    """plaintext ASCII, key ASCII 16 char -> ciphertext HEX (CBC: IV di depan)."""
    kb = validate_key(key)
    try:
        pb = plaintext.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("plaintext harus ASCII")
    return encrypt_bytes(pb, kb, mode).hex()


def decrypt(hex_cipher, key, mode="cbc"):
    kb = validate_key(key)
    pb = decrypt_bytes(bytes.fromhex(hex_cipher), kb, mode)
    return pb.decode("ascii")


# ----------------------------------------------------------------- CLI
def _selftest():
    # Vektor uji FIPS-197 Appendix C.1
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = "69c4e0d86a7b0430d8cdb78070b4c55a"
    rk = expand_key(key)
    ct = encrypt_block(pt, rk).hex()
    assert ct == expect, f"enkripsi salah: {ct}"
    assert decrypt_block(bytes.fromhex(ct), rk) == pt, "dekripsi salah"
    # Vektor FIPS-197 Appendix B
    k2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    p2 = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert encrypt_block(p2, expand_key(k2)).hex() == "3925841d02dc09fbdc118597196a0b32"
    # round-trip ECB & CBC dengan berbagai panjang
    for mode in ("ecb", "cbc"):
        for n in (0, 1, 15, 16, 17, 31, 32, 100):
            msg = "A" * n
            assert decrypt(encrypt(msg, "kunci-rahasia-16", mode), "kunci-rahasia-16", mode) == msg
    print("selftest OK (FIPS-197 C.1, B, round-trip ECB/CBC)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "selftest":
        _selftest()
    elif a[0] == "enc" and len(a) >= 3:
        print(encrypt(a[2], a[1], a[3] if len(a) > 3 else "ecb"))
    elif a[0] == "dec" and len(a) >= 3:
        print(decrypt(a[2], a[1], a[3] if len(a) > 3 else "ecb"))
    elif a[0] == "trace" and len(a) >= 3:
        kb = validate_key(a[1])
        pt = a[2].encode("ascii")
        assert len(pt) <= 16, "trace hanya untuk 1 blok (maks 16 karakter)"
        pt = pt.ljust(16, b"\x00")
        rk = expand_key(kb)
        print("key (hex)   :", kb.hex())
        for i, k in enumerate(rk):
            print(f"round key {i:2d} : {bytes(k).hex()}")
        print("plaintext   :", pt.hex())
        encrypt_block(pt, rk, trace=True)
    else:
        print(__doc__)
