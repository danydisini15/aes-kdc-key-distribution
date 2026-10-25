# Key Distribution Scenario (KDC + Alice + Bob) dengan AES-128 Manual

Python 3.8+, **tanpa library kripto** (hanya `socket`, `threading`, `secrets`, `os`).
AES dan KDC ditulis sendiri.

## File
| File | Fungsi |
|---|---|
| `aes.py` | AES-128 manual (S-Box, KeyExpansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, ECB/CBC, PKCS#7) |
| `proto.py` | Format pesan, pembuat session key & nonce |
| `kdc.py` | Server KDC (interaktif, key bisa diubah) |
| `peer.py` | Alice **dan** Bob (satu program, dua arah) |
| `test_e2e.py` | Tes otomatis 3 IP loopback (opsional) |

## Cara menjalankan (3 perangkat / 3 IP berbeda, satu jaringan/Wi-Fi/hotspot sama)
Cek IP masing-masing: `ipconfig` (Windows) / `ip a` (Linux). Contoh: KDC=192.168.1.10, Alice=192.168.1.11, Bob=192.168.1.12.

```
# Perangkat KDC
python kdc.py
#   -> diminta master key Alice & Bob (16 karakter ASCII)

# Perangkat Bob
python peer.py --name Bob --kdc 192.168.1.10:5000 --listen 6000
#   -> diminta master key Bob (HARUS sama dengan yang diisi di KDC)

# Perangkat Alice
python peer.py --name Alice --kdc 192.168.1.10:5000 --listen 6000
#   -> diminta master key Alice

# Di konsol Alice:
/connect Bob 192.168.1.12 6000
```
Setelah `AUTENTIKASI OK`, **ketik teks apa saja di Alice maupun Bob**; pesan terkirim terenkripsi AES dua arah.
Windows: izinkan Python di firewall (atau buka port 5000 dan 6000) agar koneksi masuk tidak diblokir.

### Perintah interaktif
- KDC: `users`, `setkey <nama> <key16>`, `add <nama> <key16>`, `quit`
- Peer: `/connect <nama> <ip> <port>`, `/key <key16>`, `/sk`, `/status`, `/quit`
- Ganti key tanpa restart: `setkey Bob <key baru>` di KDC **dan** `/key <key baru>` di Bob.
  Demo key salah: ubah salah satunya saja, lalu `/connect` -> gagal ("tiket tidak bisa didekripsi").

### Uji 3 IP di satu laptop (latihan)
```
python kdc.py --bind 127.0.0.1
python peer.py --name Bob   --kdc 127.0.0.1:5000 --bind 127.0.0.3
python peer.py --name Alice --kdc 127.0.0.1:5000 --bind 127.0.0.2
/connect Bob 127.0.0.3 6000
```
(127.0.0.x aktif otomatis di Linux; di Windows/macOS mungkin perlu alias IP. Untuk demo, pakai 3 perangkat sungguhan.)

## Skenario (sesuai slide 13 "Key Distribution Scenario", security_07.pdf)
| Langkah | Arah | Isi |
|---|---|---|
| 1 | A -> KDC | `IDA \|\| IDB \|\| N1` (plaintext) |
| 2 | KDC -> A | `E(Ka,[Ks \|\| IDA \|\| IDB \|\| N1]) \|\| E(Kb,[Ks \|\| IDA])` (dua ciphertext hex dipisah `\|\|`) |
| 3 | A -> B | `E(Kb,[Ks \|\| IDA])` (bagian kedua langkah 2, diteruskan apa adanya) |
| 4 | B -> A | `E(Ks, N2)` |
| 5 | A -> B | `E(Ks, f(N2))`, dengan `f(N2) = N2 + 1` |
| 6+ | A <-> B | pesan `E(Ks, teks)` (AES, dua arah) |

Alice memverifikasi `N1` dan `IDB` pada langkah 2 (anti-replay). Bob memverifikasi `f(N2)` pada langkah 5.
Alice memverifikasi `IDA`, `IDB`, `N1` hasil dekripsi bagian pertama.

### Yang ada di PPT vs yang saya tambahkan
Dari PPT: 5 langkah + notasi di atas, master key Ka/Kb, session key Ks, nonce N1/N2, fungsi f(N2), AES (slide 06: blok 128 bit, kunci 128/192/256), mode ECB/CBC (slide 04).
Tambahan (TIDAK ada di PPT, dibuat karena tugas butuh implementasi nyata): `f(N2)=N2+1` (PPT hanya menulis f), Ks 16 karakter ASCII acak, nonce acak 9 digit, AES-128 saja, CBC+IV acak dan PKCS#7, format kawat `TAG:payload` per baris lewat TCP, balasan `AUTH_OK/AUTH_FAIL` setelah langkah 5, perintah interaktif (`setkey`, `/key`, `/connect`), dan validasi ID/N1 oleh Alice.

## Wireshark
1. Pilih interface yang dipakai (Wi-Fi / Ethernet). Untuk uji loopback: `Loopback`/`lo`.
2. Capture filter (sebelum Start): `tcp port 5000 or tcp port 6000`
3. Display filter: `tcp.port == 5000 || tcp.port == 6000`
   - hanya KDC: `tcp.port == 5000`; hanya Alice-Bob: `tcp.port == 6000`
   - berdasarkan IP: `ip.addr == 192.168.1.10`
4. Klik kanan paket -> **Follow -> TCP Stream**: terlihat baris `REQ:`, `RESP:`, `TICKET:`, `NONCE:`, `NONCE_REPLY:`, `MSG:` berurutan.
   Langkah 1 terbaca (plaintext), langkah 2 s.d. 6 berupa **hex**, cocokkan dengan hex yang dicetak program.
5. Wireshark hanya bisa menangkap lalu lintas perangkat tempat ia berjalan. Jalankan di laptop KDC (melihat langkah 1-2) atau di Alice/Bob (langkah 3-6).

## Bahan penjelasan saat demo (pahami, jangan dibaca)
**AES (`aes.py`)** - blok 128 bit, key 128 bit, 10 ronde.
- `xtime/gmul`: perkalian di GF(2^8) modulo `x^8+x^4+x^3+x+1` (0x11B).
- `S-Box`: invers perkalian GF(2^8) lalu transformasi affine (+0x63); dihitung di `_build_sbox()`.
- `expand_key`: 16 byte -> 44 word -> 11 round key (RotWord, SubWord, Rcon).
- Tiap ronde: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey; ronde terakhir tanpa MixColumns. Dekripsi = invers urutannya.
- Divalidasi dengan vektor uji resmi FIPS-197 (`python aes.py selftest`).
- Lihat state tiap ronde: `python aes.py trace kunci16karakter "plaintext"`.
- Mode: CBC (IV acak 16 byte di depan ciphertext) dipakai di jaringan; ECB tersedia untuk verifikasi ke alat online (`python aes.py enc <key> <teks> ecb`). Padding PKCS#7 karena teks tidak selalu kelipatan 16 byte.
- Key & plaintext ASCII, ciphertext HEX; key wajib tepat 16 karakter.

**KDC (`kdc.py`)** - menyimpan master key tiap user (Ka, Kb). Menerima `REQ`, membuat session key Ks acak 16 karakter, membuat tiket `E(Kb, Ks|IDA)` lalu membungkusnya dalam `E(Ka, ...)`. Alice hanya bisa membuka bungkus luar, Bob hanya bisa membuka tiket; KDC tidak pernah mengirim Ks dalam bentuk plaintext.

**Pertanyaan yang mungkin ditanya**
- Kenapa ada nonce N1? Mencegah replay respons KDC lama; Alice mencocokkannya.
- Kenapa N2 dan f(N2)? Bob memastikan Alice benar-benar memegang Ks (bukan replay tiket lama).
- Kenapa CBC pakai IV? Plaintext sama menghasilkan ciphertext berbeda; ECB membocorkan pola.
- Apa kelemahan skema ini? KDC single point of failure/trust; master key harus dibagikan sebelumnya; tiket lama bisa direplay tanpa timestamp.
- Kenapa 2 arah? Setelah handshake, soket TCP yang sama dipakai dua thread (kirim dari input, terima di `recv_loop`) dengan Ks yang sama.