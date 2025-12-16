# Public Key Cryptosystem sederhana berbasis RSA
# File ini berdiri sendiri (tidak perlu import dari tugaski3) dan menunjukkan:
#   1) Enkripsi / dekripsi pesan dengan kunci publik / privat.
#   2) Tanda tangan digital (sign) dan verifikasi (verify) memakai RSA + SHA-256.
# Catatan keamanan: implementasi ini tidak memakai padding (OAEP/PSS), jadi hanya
# untuk demonstrasi konsep PKC dan signature di mata kuliah, bukan produksi.

import hashlib
from typing import Tuple

# -----------------------------
#  Kunci contoh (1024-bit RSA)
# -----------------------------
# Kunci di bawah diambil dari tugas KI 3 sehingga konsisten dengan materi sebelumnya.
# ALICE bertindak sebagai pengirim yang menandatangani pesan.
# BOB bertindak sebagai penerima yang mendekripsi pesan.

# Modulus dan eksponen milik "ALICE"
ALICE_N = 156469044316159947363884933898886215289275557992816167439134938174196403828497815972605478729001621250029908157498268904948735474704947545460771419340165518354686383430215119261634609323674502678285165178293065860108033297764529016937887524527032108070720062607739778705451732889179250323034471406939043795131
ALICE_E = 65537
ALICE_D = 19488696928128552680269650242269634369956027393722013093536251448183512800169719733103179709452452822992393131182366999195554209440530326212755648984602299379945006315604386904086035687378590518059555944370751082209851596056492019577231305754820594144169070624143923895863584007055880342460682218727266152025

# Modulus dan eksponen milik "BOB"
BOB_N = 150730967367299134506912821638860026828259042763503589024663020798515403846395263090779488980345157017349230972311269677284061798978899143908868266598363369412536356595090274511837117218103569009470786620281955435246943362781837700368360255950549005315290594762236465443234662534937805698234518207323586052059
BOB_E = 65537
BOB_D = 65045666624933556198136243117314186623486093625219749958054339117036382408133232114711996545426729300794395162174362167601647828979381664379795503025796312555449305901743227228923686931448481591899033379155247966992454998834332212185716595653818529244924448231767305247046297898629550202801998392682077740765

# Tipe alias agar mudah dibaca
PublicKey = Tuple[int, int]   # (n, e)
PrivateKey = Tuple[int, int]  # (n, d)

# Kunci publik/privat yang dipakai di demo
ALICE_PUBLIC_KEY: PublicKey = (ALICE_N, ALICE_E)
ALICE_PRIVATE_KEY: PrivateKey = (ALICE_N, ALICE_D)
BOB_PUBLIC_KEY: PublicKey = (BOB_N, BOB_E)
BOB_PRIVATE_KEY: PrivateKey = (BOB_N, BOB_D)


# -----------------------------
#  Utilitas konversi data
# -----------------------------

def _bytes_to_int(data: bytes) -> int:
    """Konversi bytes -> integer (big endian)."""
    return int.from_bytes(data, "big")


def _int_to_bytes(value: int) -> bytes:
    """Konversi integer -> bytes (panjang minimum)."""
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


# -----------------------------
#  Fungsi dasar RSA
# -----------------------------

def encrypt_int(m: int, public_key: PublicKey) -> int:
    """Enkripsi integer m dengan kunci publik (n, e)."""
    n, e = public_key
    if m < 0 or m >= n:
        raise ValueError("Plaintext integer berada di luar range modulus.")
    return pow(m, e, n)


def decrypt_int(c: int, private_key: PrivateKey) -> int:
    """Dekripsi integer c dengan kunci privat (n, d)."""
    n, d = private_key
    if c < 0 or c >= n:
        raise ValueError("Ciphertext integer berada di luar range modulus.")
    return pow(c, d, n)


# -----------------------------
#  API level teks (tanpa padding)
# -----------------------------

def encrypt_message(message: str, receiver_public_key: PublicKey) -> str:
    """Enkripsi string menjadi ciphertext hex memakai kunci publik penerima."""
    message_bytes = message.encode("utf-8")
    m_int = _bytes_to_int(message_bytes)
    c_int = encrypt_int(m_int, receiver_public_key)
    return format(c_int, "X")  # hex uppercase


def decrypt_message(cipher_hex: str, receiver_private_key: PrivateKey) -> str:
    """Dekripsi ciphertext hex menjadi string plaintext."""
    c_int = int(cipher_hex, 16)
    m_int = decrypt_int(c_int, receiver_private_key)
    plain_bytes = _int_to_bytes(m_int)
    return plain_bytes.decode("utf-8", errors="strict")


# -----------------------------
#  Signature (RSA + SHA-256)
# -----------------------------

def sign_message(message: str, signer_private_key: PrivateKey) -> str:
    """Buat tanda tangan digital untuk message. Output: signature hex."""
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    m_int = _bytes_to_int(digest)
    sig_int = decrypt_int(m_int, signer_private_key)  # RSA signing = m^d mod n
    return format(sig_int, "X")


def verify_signature(message: str, signature_hex: str, signer_public_key: PublicKey) -> bool:
    """Verifikasi tanda tangan digital."""
    expected_digest = hashlib.sha256(message.encode("utf-8")).digest()
    sig_int = int(signature_hex, 16)
    recovered_int = encrypt_int(sig_int, signer_public_key)  # RSA verify = s^e mod n
    recovered_digest = _int_to_bytes(recovered_int)
    # Pad digest hasil pemulihan dengan nol di depan bila panjang < 32 byte
    if len(recovered_digest) < 32:
        recovered_digest = b"\x00" * (32 - len(recovered_digest)) + recovered_digest
    return recovered_digest == expected_digest


# -----------------------------
#  Demo alur PKC + Signature
# -----------------------------

def demo():
    """Contoh alur: Alice mengirim pesan ke Bob (encrypt) + sign + verify."""
    message = "Kerjakan tugas KI 4 dengan aman!"

    print("=== DEMO PUBLIC KEY CRYPTOSYSTEM + SIGNATURE ===")
    print(f"Plaintext  : {message}")

    # Alice menandatangani pesan memakai kunci privat miliknya
    signature_hex = sign_message(message, ALICE_PRIVATE_KEY)
    print(f"Signature  : {signature_hex}")

    # Alice mengenkripsi pesan untuk Bob memakai kunci publik Bob
    cipher_hex = encrypt_message(message, BOB_PUBLIC_KEY)
    print(f"Ciphertext : {cipher_hex}")

    # Di sisi Bob: verifikasi tanda tangan lalu dekripsi
    is_valid = verify_signature(message, signature_hex, ALICE_PUBLIC_KEY)
    plaintext = decrypt_message(cipher_hex, BOB_PRIVATE_KEY)

    print(f"Verify OK  : {is_valid}")
    print(f"Decrypted  : {plaintext}")


if __name__ == "__main__":
    demo()
