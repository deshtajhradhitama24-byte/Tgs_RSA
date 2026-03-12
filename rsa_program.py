"""
RSA Cryptography Program
========================
Program untuk menghasilkan pasangan public key dan private key menggunakan RSA,
serta melakukan proses enkripsi dan dekripsi pesan.

Analisis Konsep Kriptografi Asimetris:
- RSA (Rivest-Shamir-Adleman) adalah algoritma kriptografi asimetris yang menggunakan
  dua kunci berbeda: Public Key (untuk enkripsi) dan Private Key (untuk dekripsi).
- Keamanan RSA didasarkan pada kesulitan memfaktorkan bilangan prima besar.
- Public Key dapat disebarkan ke siapa saja, sedangkan Private Key harus dijaga rahasia.

Fungsi Public Key dan Private Key:
- Public Key  : Digunakan untuk mengenkripsi pesan. Siapapun bisa menggunakan public key
                pengirim untuk mengenkripsi pesan yang hanya bisa dibaca oleh pemilik private key.
- Private Key : Digunakan untuk mendekripsi pesan yang dienkripsi dengan public key pasangannya.
                Hanya pemilik private key yang dapat membaca pesan terenkripsi.

Proses Enkripsi dan Dekripsi RSA:
- Enkripsi : M^e mod n  (M=pesan, e=public exponent, n=modulus)
- Dekripsi : C^d mod n  (C=ciphertext, d=private exponent, n=modulus)

Prinsip Keamanan:
- Kunci 1024-bit atau 2048-bit memastikan keamanan yang cukup kuat.
- Algoritma padding OAEP (Optimal Asymmetric Encryption Padding) dengan SHA-256
  memberikan keamanan tambahan terhadap berbagai serangan kriptografi.
- Tanpa private key yang sesuai, dekripsi secara komputasional tidak dapat dilakukan
  dalam waktu yang wajar (problem faktorisasi bilangan besar).
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


# ============================================================
# 1. GENERATE RSA KEY PAIR
# ============================================================
def generate_rsa_keys(key_size: int = 1024):
    """
    Menghasilkan pasangan kunci RSA (Public Key & Private Key).
    
    Args:
        key_size (int): Ukuran kunci dalam bits. Default 1024.
                        Pilihan umum: 1024, 2048, 4096.
    
    Returns:
        tuple: (private_key_object, public_key_object)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,       # Eksponen publik standar (e)
        key_size=key_size,           # Panjang kunci dalam bits
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ============================================================
# 2. EXPORT KEY KE FORMAT PEM (String)
# ============================================================
def export_private_key_pem(private_key) -> str:
    """
    Mengekspor private key ke format PEM string (PKCS#1).
    Format: -----BEGIN RSA PRIVATE KEY-----
    
    Args:
        private_key: Objek private key RSA.
    
    Returns:
        str: Private key dalam format PEM.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def export_public_key_pem(public_key) -> str:
    """
    Mengekspor public key ke format PEM string (SubjectPublicKeyInfo / PKCS#8).
    Format: -----BEGIN PUBLIC KEY-----
    
    Args:
        public_key: Objek public key RSA.
    
    Returns:
        str: Public key dalam format PEM.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Format standar
    )
    return pem.decode('utf-8')


# ============================================================
# 3. LOAD KEY DARI STRING PEM
# ============================================================
def load_public_key_from_pem(pem_string: str):
    """
    Memuat public key dari string PEM.
    Mendukung format:
    - -----BEGIN PUBLIC KEY----- (SubjectPublicKeyInfo)
    - -----BEGIN RSA PUBLIC KEY----- (PKCS#1)
    
    Args:
        pem_string (str): Public key dalam format PEM.
    
    Returns:
        Public key object.
    
    Raises:
        ValueError: Jika format PEM tidak valid.
    """
    pem_bytes = pem_string.strip().encode('utf-8')
    
    if b"BEGIN RSA PUBLIC KEY" in pem_bytes:
        return serialization.load_pem_public_key(pem_bytes)
    else:
        return serialization.load_pem_public_key(pem_bytes)


def load_private_key_from_pem(pem_string: str):
    """
    Memuat private key dari string PEM.
    
    Args:
        pem_string (str): Private key dalam format PEM.
    
    Returns:
        Private key object.
    
    Raises:
        ValueError: Jika format PEM tidak valid.
    """
    pem_bytes = pem_string.strip().encode('utf-8')
    return serialization.load_pem_private_key(pem_bytes, password=None)


# ============================================================
# 4. ENKRIPSI PESAN
# ============================================================
def encrypt_message(plaintext: str, public_key) -> str:
    """
    Mengenkripsi pesan teks menggunakan RSA dengan padding OAEP + SHA-256.
    
    Algoritma: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
    - OAEP (Optimal Asymmetric Encryption Padding): Padding yang aman untuk RSA.
    - SHA-256: Hash function yang digunakan dalam proses padding.
    - MGF1: Mask Generation Function berbasis SHA-256.
    
    Args:
        plaintext (str): Pesan asli yang akan dienkripsi.
        public_key: Objek public key RSA.
    
    Returns:
        str: Ciphertext dalam format Base64.
    
    Raises:
        ValueError: Jika pesan terlalu panjang untuk ukuran kunci.
        Exception: Jika terjadi error saat enkripsi.
    """
    message_bytes = plaintext.encode('utf-8')
    
    encrypted_bytes = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),   # MGF1 dengan SHA-256
            algorithm=hashes.SHA256(),                      # Hash utama SHA-256
            label=None
        )
    )
    
    # Encode hasil enkripsi ke Base64 agar mudah ditampilkan/disimpan
    cipher_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return cipher_base64


# ============================================================
# 5. DEKRIPSI PESAN
# ============================================================
def decrypt_message(cipher_base64: str, private_key) -> str:
    """
    Mendekripsi ciphertext Base64 menggunakan RSA dengan padding OAEP + SHA-256.
    
    Algoritma: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
    
    Args:
        cipher_base64 (str): Ciphertext dalam format Base64.
        private_key: Objek private key RSA yang sesuai dengan public key enkripsi.
    
    Returns:
        str: Pesan asli (plaintext).
    
    Raises:
        ValueError: Jika ciphertext tidak valid atau kunci tidak cocok.
        Exception: Jika terjadi error saat dekripsi.
    """
    # Decode dari Base64 ke bytes
    encrypted_bytes = base64.b64decode(cipher_base64)
    
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),   # Harus sama dengan saat enkripsi
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_bytes.decode('utf-8')


# ============================================================
# 6. DEMO / TEST (jalankan langsung tanpa GUI)
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("   RSA CRYPTOGRAPHY PROGRAM")
    print("   Algoritma: RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    print("=" * 60)

    # --- Generate Key ---
    print("\n[1] Generating RSA Key Pair (1024-bit)...")
    priv_key, pub_key = generate_rsa_keys(key_size=1024)

    pub_pem  = export_public_key_pem(pub_key)
    priv_pem = export_private_key_pem(priv_key)

    print("\n--- PUBLIC KEY ---")
    print(pub_pem)

    print("--- PRIVATE KEY ---")
    print(priv_pem)

    # --- Enkripsi ---
    pesan = "firman"
    print(f"\n[2] Enkripsi pesan: '{pesan}'")
    cipher = encrypt_message(pesan, pub_key)
    print(f"Ciphertext (Base64):\n{cipher}")

    # --- Dekripsi ---
    print(f"\n[3] Dekripsi ciphertext...")
    hasil = decrypt_message(cipher, priv_key)
    print(f"Hasil Dekripsi: '{hasil}'")

    # --- Verifikasi ---
    print("\n[4] Verifikasi:")
    if hasil == pesan:
        print(f"✓ BERHASIL! Pesan asli == Hasil dekripsi: '{hasil}'")
    else:
        print(f"✗ GAGAL! Pesan tidak cocok.")

    # --- Demo: Load key dari string PEM (seperti input manual di GUI) ---
    print("\n[5] Test Load Key dari PEM String...")
    loaded_pub  = load_public_key_from_pem(pub_pem)
    loaded_priv = load_private_key_from_pem(priv_pem)

    cipher2 = encrypt_message("test load key", loaded_pub)
    hasil2  = decrypt_message(cipher2, loaded_priv)
    print(f"Enkripsi + Dekripsi dengan loaded key: '{hasil2}'")
    print("✓ Load key dari PEM string berhasil!")

    print("\n" + "=" * 60)
    print("   Program selesai.")
    print("=" * 60)