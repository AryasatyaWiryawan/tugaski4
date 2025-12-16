# chat_server.py - server percakapan DES + RSA key exchange + signature
#
# Fitur tambahan untuk tugas 4:
# - Session key DES dikirim via RSA dan ditandatangani (integrity + authenticity).
# - Setiap pesan chat dikirim sebagai MSG:<cipher_hex>:<sig_hex>
#   cipher_hex = hasil DES, sig_hex = signature RSA atas ciphertext.
# - Public Key Authority disimulasikan lewat rsa.get_public_key().

import socket
import sys
import threading
import os

from DES import encrypt_text_with_trace, decrypt_text_with_trace
import rsa

# Prefix untuk jenis pesan
KEYX_PREFIX = "KEYX:"
MSG_PREFIX = "MSG:"

# Separator sederhana antara ciphertext dan signature
SEPARATOR = ":"

# Kunci sesi DES (akan terisi setelah key exchange)
SESSION_KEY_HEX = None

# Konfigurasi default host dan port
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000


def generate_des_session_key():
    """Bangkitkan kunci DES 64-bit (8 byte) dan kembalikan dalam bentuk hex 16 karakter."""
    key_bytes = os.urandom(8)  # 8 byte = 64 bit
    return key_bytes.hex().upper()


def send_des_key_via_rsa(conn):
    """Server membangkitkan kunci DES, mengenkripsi dengan RSA, lalu menandatangani cipher."""
    global SESSION_KEY_HEX

    # 1) generate kunci sesi DES
    SESSION_KEY_HEX = generate_des_session_key()
    key_bytes = bytes.fromhex(SESSION_KEY_HEX)
    m_int = int.from_bytes(key_bytes, "big")

    # 2) ambil kunci publik client dari PKA
    client_pub = rsa.get_public_key("client")  # (n, e)

    # 3) enkripsi kunci DES memakai rsa
    c_int = rsa.encrypt_int(m_int, client_pub)
    cipher_hex = format(c_int, "X")

    # 4) tanda tangani ciphertext agar client bisa memverifikasi sumber
    sig_hex = rsa.sign_str(cipher_hex, rsa.SERVER_PRIVATE_KEY)

    # 5) kirim ke client
    msg = f"{KEYX_PREFIX}{cipher_hex}{SEPARATOR}{sig_hex}\n"
    conn.sendall(msg.encode())

    print("\n[Key Exchange] Mengirim session key DES ke client (rsa + signed)")
    print(f"[Key Exchange] DES key (hex)    : {SESSION_KEY_HEX}")
    print(f"[Key Exchange] rsa cipher (hex) : {cipher_hex}")
    print(f"[Key Exchange] signature (hex)  : {sig_hex}")


def recv_loop(conn):
    """Loop penerima pesan dari client (ciphertext DES + signature)."""
    global SESSION_KEY_HEX
    buffer = b""  # buffer untuk kumpulkan data sampai newline

    while True:
        chunk = conn.recv(4096)
        if not chunk:
            print("\n[Disconnected]")
            break
        buffer += chunk

        # Proses per-baris dipisahkan dengan newline
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                text = line.decode().strip()
                if not text:
                    continue

                if not text.startswith(MSG_PREFIX):
                    print(f"\n[Warning] Format pesan tidak dikenal: {text}")
                    continue

                if SESSION_KEY_HEX is None:
                    print("\n[Warning] Pesan masuk sebelum session key siap.")
                    print(" Raw cipher:", text)
                    continue

                # Format: MSG:<cipher_hex>:<sig_hex>
                try:
                    payload = text[len(MSG_PREFIX):]
                    cipher_hex, sig_hex = payload.split(SEPARATOR, 1)
                except ValueError:
                    print(f"\n[Warning] Format MSG tidak valid: {text}")
                    continue

                # Verifikasi signature dari client
                if not rsa.verify_str(cipher_hex, sig_hex, rsa.get_public_key("client")):
                    print("\n[Warning] Signature pesan tidak valid, pesan diabaikan.")
                    continue

                # Dekripsi dengan DES
                plaintext, trace = decrypt_text_with_trace(cipher_hex, SESSION_KEY_HEX)

                print("\n--- Decrypt Process (Server) ---")
                print(trace)
                print(f"<peer> {plaintext}")
            except Exception as exc:
                print(f"\n[Decode error] {exc} (raw={line!r})")


def main():
    """Fungsi utama server."""
    global SESSION_KEY_HEX

    # Baca argumen host & port jika ada
    if len(sys.argv) == 1:
        host, port = DEFAULT_HOST, DEFAULT_PORT
    elif len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("Usage: python chat_server.py [host port]")
        sys.exit(1)

    # Siapkan socket TCP
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print(f"[Listening] {host}:{port} ...")

    # Tunggu client terhubung
    conn, addr = srv.accept()
    print(f"[Connected] from {addr}")

    # Lakukan distribusi kunci DES via rsa (ditandatangani)
    send_des_key_via_rsa(conn)

    # Jalankan thread terpisah untuk menerima pesan
    t = threading.Thread(target=recv_loop, args=(conn,), daemon=True)
    t.start()

    # Loop utama untuk mengirim pesan ke client
    try:
        while True:
            msg = input("> ")
            if not msg:
                continue

            if SESSION_KEY_HEX is None:
                print("[Error] Session key belum siap, tidak bisa enkripsi pesan.")
                continue

            try:
                cipher_hex, trace = encrypt_text_with_trace(msg, SESSION_KEY_HEX)

                print("\n--- Encrypt Process (Server) ---")
                print(trace)

                # Tanda tangani ciphertext dengan kunci privat server
                sig_hex = rsa.sign_str(cipher_hex, rsa.SERVER_PRIVATE_KEY)
                payload = f"{MSG_PREFIX}{cipher_hex}{SEPARATOR}{sig_hex}\n"
                conn.sendall(payload.encode())
            except Exception as exc:
                print(f"[Encrypt/Send error] {exc}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        # Tutup koneksi dan socket
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        srv.close()
        print("\n[Server closed]")


if __name__ == "__main__":
    main()
