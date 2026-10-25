"""
kdc.py - Key Distribution Center (manual, interaktif).

Jalankan:
  python kdc.py                       # akan menanyakan master key Alice & Bob
  python kdc.py --port 5000 --bind 0.0.0.0
  python kdc.py --alice-key <16char> --bob-key <16char>   # opsional (untuk uji)

Perintah di konsol KDC (saat berjalan, tanpa restart):
  users                    tampilkan daftar user (key disembunyikan sebagian)
  setkey <nama> <key16>    ubah master key user
  add <nama> <key16>       tambah user baru
  quit
"""
import argparse
import socket
import threading

import aes
import proto

keys = {}                 # nama -> master key (ASCII 16 char)
lock = threading.Lock()


def log(msg):
    print(msg, flush=True)


def handle(conn, addr):
    rf = conn.makefile("r", encoding="ascii", newline="\n")
    try:
        conn.settimeout(15)
        tag, payload = proto.recv_line(rf)
        if tag != "REQ":
            proto.send_line(conn, "ERR", "pesan tidak dikenal")
            return
        log(f"\n[KDC] === Langkah 1 diterima dari {addr[0]}:{addr[1]} ===")
        log(f"[KDC] REQ (plaintext): {payload}")
        try:
            id_a, id_b, n1 = payload.split(proto.SEP)
        except ValueError:
            proto.send_line(conn, "ERR", "format REQ salah")
            return
        with lock:
            ka, kb = keys.get(id_a), keys.get(id_b)
        if ka is None or kb is None:
            miss = id_a if ka is None else id_b
            log(f"[KDC] user '{miss}' tidak terdaftar -> ditolak")
            proto.send_line(conn, "ERR", f"user {miss} tidak terdaftar")
            return

        # --- Langkah 2: E(Ka,[Ks||IDA||IDB||N1]) || E(Kb,[Ks||IDA]) ---
        ks = proto.gen_session_key()
        part_a_plain = proto.SEP.join([ks, id_a, id_b, n1])
        part_b_plain = proto.SEP.join([ks, id_a])
        part_a = aes.encrypt(part_a_plain, ka)                           # untuk Alice
        part_b = aes.encrypt(part_b_plain, kb)                           # tiket untuk Bob
        resp = part_a + proto.SEP + part_b                               # hex || hex
        log(f"[KDC] === Langkah 2: kirim ke {id_a} ===")
        log(f"[KDC] Session key Ks         : {ks}")
        log(f"[KDC] Bagian-A plain         : {part_a_plain}")
        log(f"[KDC] Bagian-A E(Ka)  (hex)  : {part_a}")
        log(f"[KDC] Bagian-B plain (tiket) : {part_b_plain}")
        log(f"[KDC] Bagian-B E(Kb)  (hex)  : {part_b}")
        proto.send_line(conn, "RESP", resp)
    except Exception as e:
        log(f"[KDC] error: {e}")
    finally:
        try:
            rf.close()
            conn.close()
        except OSError:
            pass


def server(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(5)
    log(f"[KDC] listening di {bind}:{port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def ask_key(nama):
    while True:
        k = input(f"Master key {nama} (16 karakter ASCII): ")
        try:
            aes.validate_key(k)
            return k
        except ValueError as e:
            print("  ->", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--alice-key")
    ap.add_argument("--bob-key")
    a = ap.parse_args()

    keys["Alice"] = a.alice_key or ask_key("Alice")
    keys["Bob"] = a.bob_key or ask_key("Bob")
    for n in ("Alice", "Bob"):
        aes.validate_key(keys[n])

    threading.Thread(target=server, args=(a.bind, a.port), daemon=True).start()
    log("Perintah: users | setkey <nama> <key16> | add <nama> <key16> | quit")
    while True:
        try:
            cmd = input("KDC> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd[0] == "quit":
            break
        elif cmd[0] == "users":
            with lock:
                for n, k in keys.items():
                    log(f"  {n}: {k[:2]}{'*' * 12}{k[-2:]}")
        elif cmd[0] in ("setkey", "add") and len(cmd) == 3:
            try:
                aes.validate_key(cmd[2])
            except ValueError as e:
                log(f"  -> {e}")
                continue
            if cmd[0] == "setkey" and cmd[1] not in keys:
                log("  -> user belum ada (pakai 'add')")
                continue
            with lock:
                keys[cmd[1]] = cmd[2]
            log(f"  -> key {cmd[1]} diperbarui")
        else:
            log("  perintah tidak dikenal")


if __name__ == "__main__":
    main()
