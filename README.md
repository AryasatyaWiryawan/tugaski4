# tugaski4

Pengembangan dari tugas KI 3: percakapan DES dengan pertukaran kunci RSA, ditambah signature (Public Key Cryptosystem) untuk autentikasi.

## Isi folder
- `chat_server.py` — server chat, kirim session key DES via RSA + signature, pesan chat ditandatangani.
- `chat_client.py` — client chat, verifikasi signature untuk key exchange dan pesan.
- `rsa.py` — utilitas RSA + fungsi sign/verify (SHA-256, tanpa padding, untuk demo).
- `DES.py` — implementasi DES dari tugas 3.
- `RSA_key_gen.py` — alat pembangkit kunci RSA contoh.
- `public_key_crypto.py` — contoh mandiri PKC + signature (demo cepat).

## Menjalankan percakapan
1. Buka terminal server:
   ```
   python chat_server.py
   ```
2. Buka terminal lain sebagai client:
   ```
   python chat_client.py 127.0.0.1 5000
   ```
3. Server akan mengirim session key DES yang dienkripsi RSA dan ditandatangani. Client memverifikasi signature sebelum menyimpan kunci.
4. Pesan dikirim sebagai `MSG:<cipher_hex>:<signature>`; penerima memverifikasi signature lalu mendekripsi dengan DES.

## Demo mandiri PKC + signature
```
python public_key_crypto.py
```
Demo menandatangani pesan, mengenkripsi untuk penerima, memverifikasi, dan mendekripsi kembali.
