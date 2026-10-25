"""Tes otomatis: KDC + Alice + Bob sebagai 3 proses, 3 IP loopback berbeda."""
import subprocess, sys, time, threading

PY = sys.executable
KA, KB = "AliceMasterKey16", "BobMasterKey1234"
procs = {}
outs = {"kdc": [], "alice": [], "bob": []}


def start(name, args):
    p = subprocess.Popen([PY, "-u"] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, bufsize=1)
    procs[name] = p
    threading.Thread(target=lambda: [outs[name].append(l) for l in p.stdout], daemon=True).start()


def say(name, line):
    procs[name].stdin.write(line + "\n")
    procs[name].stdin.flush()


start("kdc", ["kdc.py", "--bind", "127.0.0.1", "--alice-key", KA, "--bob-key", KB])
time.sleep(0.7)
start("bob", ["peer.py", "--name", "Bob", "--kdc", "127.0.0.1:5000", "--listen", "6000",
              "--bind", "127.0.0.3", "--key", KB])
start("alice", ["peer.py", "--name", "Alice", "--kdc", "127.0.0.1:5000", "--listen", "6000",
                "--bind", "127.0.0.2", "--key", KA])
time.sleep(0.7)
say("alice", "/connect Bob 127.0.0.3 6000")
time.sleep(1.5)
say("alice", "Halo Bob, ini pesan dari Alice!")
time.sleep(0.7)
say("bob", "Halo Alice, pesan balasan dari Bob.")
time.sleep(0.7)
# ganti key Bob di KDC dan di Bob tanpa restart, lalu sesi baru
say("kdc", "setkey Bob NewBobKey9876543")
say("bob", "/key WrongKeyWrongKey")          # sengaja salah dulu -> harus gagal
time.sleep(0.5)
say("alice", "/connect Bob 127.0.0.3 6000")
time.sleep(1.5)
say("bob", "/key NewBobKey9876543")          # benar -> harus berhasil
time.sleep(0.3)
say("alice", "/connect Bob 127.0.0.3 6000")
time.sleep(1.5)
say("alice", "pesan setelah ganti key")
time.sleep(0.7)
for n in procs:
    say(n, "/quit" if n != "kdc" else "quit")
time.sleep(0.5)
for n in procs:
    procs[n].terminate()
for n in ("kdc", "alice", "bob"):
    print(f"\n######## {n.upper()} ########")
    print("".join(outs[n]))

txt = "".join(outs["alice"]) + "".join(outs["bob"])
assert "Halo Bob, ini pesan dari Alice!" in "".join(outs["bob"]), "Bob tidak menerima pesan Alice"
assert "Halo Alice, pesan balasan dari Bob." in "".join(outs["alice"]), "Alice tidak menerima pesan Bob"
assert "tiket TIDAK bisa didekripsi" in "".join(outs["bob"]), "key salah harus gagal"
assert "pesan setelah ganti key" in "".join(outs["bob"]), "ganti key gagal"
print("\n==== SEMUA TES LULUS ====")
