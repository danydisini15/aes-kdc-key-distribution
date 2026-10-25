"""
peer.py - Alice / Bob (satu program, peran ditentukan --name dan siapa yang inisiasi).

Jalankan (contoh, 3 mesin berbeda):
  KDC   (192.168.1.10): python kdc.py
  Bob   (192.168.1.12): python peer.py --name Bob   --kdc 192.168.1.10:5000 --listen 6000
  Alice (192.168.1.11): python peer.py --name Alice --kdc 192.168.1.10:5000 --listen 6000
Lalu di Alice:  /connect Bob 192.168.1.12 6000
Setelah langkah 1-5 selesai, kedua sisi bisa saling mengetik pesan (dua arah, AES).

Perintah:
  /connect <nama_lawan> <ip> <port>   mulai skenario KDC (peran Alice / inisiator)
  /key <key16>                        ganti master key sendiri (harus sama dgn di KDC)
  /sk                                 tampilkan session key aktif
  /status                             status sesi
  /quit
  teks biasa                          kirim pesan terenkripsi AES ke lawan
"""
import argparse
import socket
import threading

import aes
import proto


class Peer:
    def __init__(self, name, key, kdc, listen_port, bind_ip):
        self.name, self.key = name, key
        self.kdc = kdc
        self.listen_port = listen_port
        self.bind_ip = bind_ip
        self.sock = None
        self.ks = None
        self.remote = None
        self.prompt = f"{name}> "

    # ---------------------------------------------------------------- util
    def say(self, msg):
        print(f"\r{msg}\n{self.prompt}", end="", flush=True)

    def new_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.bind_ip != "0.0.0.0":
            s.bind((self.bind_ip, 0))      # paksa source IP (untuk uji 3 IP di 1 mesin)
        return s

    # ------------------------------------------------------ peran penerima
    def start_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_ip, self.listen_port))
        s.listen(5)
        threading.Thread(target=self.accept_loop, args=(s,), daemon=True).start()
        print(f"[{self.name}] listen di {self.bind_ip}:{self.listen_port}")

    def accept_loop(self, s):
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.incoming, args=(conn, addr), daemon=True).start()

    def incoming(self, conn, addr):
        """Sisi 'Bob': terima langkah 3, jalankan langkah 4 dan 5."""
        rf = conn.makefile("r", encoding="ascii", newline="\n")
        try:
            conn.settimeout(15)
            tag, payload = proto.recv_line(rf)
            if tag != "TICKET":
                proto.send_line(conn, "AUTH_FAIL", "mengharapkan TICKET")
                return
            self.say(f"[{self.name}] === Langkah 3 dari {addr[0]}:{addr[1]} ===\n"
                     f"[{self.name}] tiket E(Kb) (hex): {payload}")
            try:
                plain = aes.decrypt(payload, self.key)
                ks, id_a = plain.split(proto.SEP)
                aes.validate_key(ks)
            except Exception:
                self.say(f"[{self.name}] tiket TIDAK bisa didekripsi (master key beda dgn KDC?)")
                proto.send_line(conn, "AUTH_FAIL", "tiket tidak valid")
                return
            self.say(f"[{self.name}] tiket plain: {plain}  -> Ks={ks}, lawan={id_a}")

            n2 = proto.gen_nonce()                                   # Langkah 4
            c4 = aes.encrypt(str(n2), ks)
            self.say(f"[{self.name}] === Langkah 4: kirim E(Ks, N2) ===\n"
                     f"[{self.name}] N2={n2}  hex={c4}")
            proto.send_line(conn, "NONCE", c4)

            tag, payload = proto.recv_line(rf)                       # Langkah 5
            if tag != "NONCE_REPLY":
                proto.send_line(conn, "AUTH_FAIL", "mengharapkan NONCE_REPLY")
                return
            val = int(aes.decrypt(payload, ks))
            self.say(f"[{self.name}] === Langkah 5 diterima ===\n"
                     f"[{self.name}] hex={payload}  f(N2)={val}  (harus {proto.f(n2)})")
            if val != proto.f(n2):
                proto.send_line(conn, "AUTH_FAIL", "f(N2) salah")
                return
            proto.send_line(conn, "AUTH_OK")
            self.say(f"[{self.name}] AUTENTIKASI OK. Sesi AES dengan {id_a} aktif.")
            self.activate(conn, rf, ks, id_a)
        except Exception as e:
            self.say(f"[{self.name}] handshake gagal: {e}")
            try:
                conn.close()
            except OSError:
                pass

    # --------------------------------------------------- peran inisiator
    def connect(self, peer_name, ip, port):
        """Sisi 'Alice': langkah 1-5."""
        # Langkah 1
        n1 = proto.gen_nonce()
        req = proto.SEP.join([self.name, peer_name, str(n1)])
        k = self.new_socket()
        k.settimeout(15)
        k.connect(self.kdc)
        krf = k.makefile("r", encoding="ascii", newline="\n")
        print(f"[{self.name}] === Langkah 1: kirim ke KDC {self.kdc[0]}:{self.kdc[1]} ===")
        print(f"[{self.name}] REQ (plaintext): {req}")
        proto.send_line(k, "REQ", req)
        tag, payload = proto.recv_line(krf)
        k.close()
        if tag != "RESP":
            print(f"[{self.name}] KDC menolak: {payload}")
            return
        # Langkah 2
        print(f"[{self.name}] === Langkah 2 diterima ===\n[{self.name}] E(Ka) hex: {payload}")
        try:
            hex_a, ticket = payload.split(proto.SEP)        # E(Ka,[...]) || E(Kb,[...])
            ks, id_a_back, id_b, n1_back = aes.decrypt(hex_a, self.key).split(proto.SEP)
        except Exception:
            print(f"[{self.name}] respons KDC tidak bisa didekripsi (master key beda dgn KDC?)")
            return
        if id_a_back != self.name or id_b != peer_name or n1_back != str(n1):
            print(f"[{self.name}] IDA/IDB/N1 tidak cocok -> kemungkinan replay/palsu, dibatalkan")
            return
        print(f"[{self.name}] Ks={ks}  N1 cocok  tiket(hex)={ticket}")

        # Langkah 3
        s = self.new_socket()
        s.settimeout(15)
        s.connect((ip, port))
        rf = s.makefile("r", encoding="ascii", newline="\n")
        print(f"[{self.name}] === Langkah 3: kirim tiket ke {peer_name} {ip}:{port} ===")
        proto.send_line(s, "TICKET", ticket)
        # Langkah 4
        tag, payload = proto.recv_line(rf)
        if tag != "NONCE":
            print(f"[{self.name}] ditolak lawan: {payload}")
            s.close()
            return
        n2 = int(aes.decrypt(payload, ks))
        print(f"[{self.name}] === Langkah 4 diterima ===\n[{self.name}] hex={payload}  N2={n2}")
        # Langkah 5
        c5 = aes.encrypt(str(proto.f(n2)), ks)
        print(f"[{self.name}] === Langkah 5: kirim E(Ks, f(N2)) ===\n"
              f"[{self.name}] f(N2)={proto.f(n2)}  hex={c5}")
        proto.send_line(s, "NONCE_REPLY", c5)
        tag, payload = proto.recv_line(rf)
        if tag != "AUTH_OK":
            print(f"[{self.name}] autentikasi gagal: {payload}")
            s.close()
            return
        print(f"[{self.name}] AUTENTIKASI OK. Sesi AES dengan {peer_name} aktif.")
        self.activate(s, rf, ks, peer_name)

    # ------------------------------------------------------ sesi AES 2 arah
    def activate(self, sock, rf, ks, remote):
        sock.settimeout(None)
        self.sock, self.ks, self.remote = sock, ks, remote
        threading.Thread(target=self.recv_loop, args=(sock, rf, ks, remote), daemon=True).start()

    def recv_loop(self, sock, rf, ks, remote):
        try:
            while True:
                tag, payload = proto.recv_line(rf)
                if tag == "MSG":
                    try:
                        text = aes.decrypt(payload, ks)
                    except Exception:
                        text = "<gagal dekripsi>"
                    self.say(f"[{remote} -> {self.name}] cipher(hex)={payload}\n"
                             f"    plaintext: {text}")
        except Exception:
            pass
        if self.sock is sock:
            self.sock = self.ks = self.remote = None
        self.say(f"[{self.name}] sesi dengan {remote} ditutup.")

    def send_msg(self, text):
        if not self.sock:
            print("Belum ada sesi. Pakai /connect dulu, atau tunggu lawan connect.")
            return
        try:
            c = aes.encrypt(text, self.ks)
        except ValueError as e:
            print(f"  -> {e}")
            return
        print(f"[{self.name} -> {self.remote}] plaintext: {text}\n    cipher(hex)={c}")
        proto.send_line(self.sock, "MSG", c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="Alice atau Bob (harus terdaftar di KDC)")
    ap.add_argument("--kdc", required=True, help="ip:port KDC, contoh 192.168.1.10:5000")
    ap.add_argument("--listen", type=int, default=6000)
    ap.add_argument("--bind", default="0.0.0.0", help="IP lokal (opsional)")
    ap.add_argument("--key", help="master key 16 char (opsional; kalau kosong ditanya)")
    a = ap.parse_args()

    key = a.key
    while True:
        if key is None:
            key = input(f"Master key {a.name} (16 karakter ASCII): ")
        try:
            aes.validate_key(key)
            break
        except ValueError as e:
            print("  ->", e)
            key = None
    host, _, port = a.kdc.rpartition(":")
    p = Peer(a.name, key, (host, int(port)), a.listen, a.bind)
    p.start_listener()
    print("Perintah: /connect <nama> <ip> <port> | /key <key16> | /sk | /status | /quit")
    while True:
        try:
            line = input(p.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.startswith("/"):
            c = line.split()
            if c[0] == "/quit":
                break
            elif c[0] == "/connect" and len(c) == 4:
                try:
                    p.connect(c[1], c[2], int(c[3]))
                except Exception as e:
                    print(f"[{p.name}] gagal: {e}")
            elif c[0] == "/key" and len(c) == 2:
                try:
                    aes.validate_key(c[1])
                    p.key = c[1]
                    print("  -> master key diganti (samakan dengan 'setkey' di KDC)")
                except ValueError as e:
                    print("  ->", e)
            elif c[0] == "/sk":
                print("  session key:", p.ks)
            elif c[0] == "/status":
                print("  sesi dengan:", p.remote or "-")
            else:
                print("  perintah tidak dikenal")
        else:
            p.send_msg(line)


if __name__ == "__main__":
    main()
