# chat_client.py - client percakapan dengan DES + distribusi kunci via rsa + signature
#
# Alur:
# - Server mengirim session key DES yang dienkripsi RSA dan ditandatangani.
# - Client memverifikasi signature, mendekripsi key, lalu menyimpannya.
# - Pesan chat dikirim dalam format MSG:<cipher_hex>:<sig_hex>
#   cipher_hex = hasil DES, sig_hex = signature RSA atas ciphertext.

import socket
import sys
import threading

from DES import encrypt_text, decrypt_text
import rsa

# Prefix untuk jenis pesan
KEYX_PREFIX = "KEYX:"
MSG_PREFIX = "MSG:"

# Separator sederhana antara ciphertext dan signature
SEPARATOR = ":"

# Kunci sesi DES (akan terisi setelah key exchange)
SESSION_KEY_HEX = None

# Konfigurasi default alamat server
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def handle_key_exchange_message(text: str):
    """Proses pesan KEYX -> verifikasi signature -> dekripsi DES key."""
    global SESSION_KEY_HEX

    # Format: KEYX:<cipher_hex>:<sig_hex>
    try:
        payload = text[len(KEYX_PREFIX):]
        cipher_hex, sig_hex = payload.split(SEPARATOR, 1)
    except ValueError:
        print("[Key Exchange] Format KEYX tidak valid.")
        return

    if not cipher_hex or not sig_hex:
        print("[Key Exchange] Cipher atau signature kosong.")
        return

    # Verifikasi signature memakai public key server (via PKA)
    if not rsa.verify_str(cipher_hex, sig_hex, rsa.get_public_key("server")):
        print("[Key Exchange] Signature KEYX tidak valid! Abaikan kunci.")
        return

    try:
        # Ubah ciphertext dari hex -> integer
        c_int = int(cipher_hex, 16)

        # Dekripsi dengan kunci privat milik client
        m_int = rsa.decrypt_int(c_int, rsa.CLIENT_PRIVATE_KEY)

        # Session key DES = 8 byte
        key_bytes = m_int.to_bytes(8, "big")
        SESSION_KEY_HEX = key_bytes.hex().upper()

        print("\n[Key Exchange] Session key DES diterima dari server (rsa + signed)")
        print(f"[Key Exchange] DES key (hex): {SESSION_KEY_HEX}")
    except Exception as exc:
        print(f"[Key Exchange ERROR] {exc}")


def recv_loop(sock):
    """Loop penerima pesan dari server."""
    global SESSION_KEY_HEX
    buffer = b""  # buffer untuk kumpulkan data sampai newline

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            print("\n[Disconnected]")
            break
        buffer += chunk

        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                text = line.decode().strip()
                if not text:
                    continue

                # Pesan khusus untuk distribusi kunci
                if text.startswith(KEYX_PREFIX):
                    handle_key_exchange_message(text)
                    continue

                if not text.startswith(MSG_PREFIX):
                    print(f"\n[Warning] Format pesan tidak dikenal: {text}")
                    continue

                if SESSION_KEY_HEX is None:
                    print("\n[Warning] Cipher diterima tetapi session key belum ada.")
                    print(" Raw cipher:", text)
                    continue

                # Format: MSG:<cipher_hex>:<sig_hex>
                try:
                    payload = text[len(MSG_PREFIX):]
                    cipher_hex, sig_hex = payload.split(SEPARATOR, 1)
                except ValueError:
                    print(f"\n[Warning] Format MSG tidak valid: {text}")
                    continue

                # Verifikasi signature dengan public key server
                if not rsa.verify_str(cipher_hex, sig_hex, rsa.get_public_key("server")):
                    print("\n[Warning] Signature pesan tidak valid, pesan diabaikan.")
                    continue

                plaintext = decrypt_text(cipher_hex, SESSION_KEY_HEX)
                print(f"\n<peer>: {plaintext}")
            except Exception as exc:
                print(f"\n[Decode error] {exc} (raw={line!r})")


def main():
    """Fungsi utama client."""
    global SESSION_KEY_HEX

    # Baca host & port server
    if len(sys.argv) == 1:
        host, port = DEFAULT_HOST, DEFAULT_PORT
    elif len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("Usage: python chat_client.py [server_host port]")
        sys.exit(1)

    # Koneksi ke server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[Connected] to {host}:{port}")

    # Thread untuk menerima pesan
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()

    # Loop utama: kirim pesan ke server
    try:
        while True:
            msg = input("> ")
            if not msg:
                continue

            if SESSION_KEY_HEX is None:
                print("[Info] Session key belum diterima, tunggu pesan [Key Exchange].")
                continue

            try:
                cipher_hex = encrypt_text(msg, SESSION_KEY_HEX)
                # Tanda tangani ciphertext dengan kunci privat client
                sig_hex = rsa.sign_str(cipher_hex, rsa.CLIENT_PRIVATE_KEY)
                payload = f"{MSG_PREFIX}{cipher_hex}{SEPARATOR}{sig_hex}\n"
                sock.sendall(payload.encode())
            except Exception as exc:
                print(f"[Encrypt/Send error] {exc}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
        print("\n[Client closed]")


if __name__ == "__main__":
    main()
