from PIL import Image
import numpy as np
import os, hashlib, base64
from cryptography.fernet import Fernet

# ================== CRYPTO + DNA HELPERS ==================

def derive_key_from_password(password: str) -> bytes:
    h = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(h)

def encrypt_text(plain_text: str, password: str):
    """
    Returns: cipher (base64 str), text_hash (hex SHA-256)
    """
    text_hash = hashlib.sha256(plain_text.encode("utf-8")).hexdigest()
    key = derive_key_from_password(password)
    f = Fernet(key)
    cipher = f.encrypt(plain_text.encode("utf-8")).decode("utf-8")
    return cipher, text_hash

def decrypt_text(cipher: str, password: str):
    key = derive_key_from_password(password)
    f = Fernet(key)
    return f.decrypt(cipher.encode("utf-8")).decode("utf-8")

BASE_MAP = {"00": "A", "01": "C", "10": "G", "11": "T"}
REV_MAP  = {v: k for k, v in BASE_MAP.items()}

def text_to_binary(s: str) -> str:
    return "".join(format(ord(c), "08b") for c in s)

def binary_to_text(b: str) -> str:
    chars = [b[i:i+8] for i in range(0, len(b), 8)]
    return "".join(chr(int(x, 2)) for x in chars if len(x) == 8)

def binary_to_dna(bits: str) -> str:
    if len(bits) % 2 != 0:
        bits += "0"
    return "".join(BASE_MAP[bits[i:i+2]] for i in range(0, len(bits), 2))

def dna_to_binary(dna: str) -> str:
    return "".join(REV_MAP[b] for b in dna)

def gc_content(dna: str) -> float:
    if not dna:
        return 0.0
    gc = dna.count("G") + dna.count("C")
    return (gc / len(dna)) * 100.0

# length header: 32 bits -> 16 DNA bases
HEADER_BASES = 16
HEADER_BITS  = HEADER_BASES * 2

def build_dna_payload(secret_text: str, password: str) -> str:
    """
    secret_text + password -> AES cipher + SHA hash -> binary -> DNA
    Returns full DNA string (header + body).
    """
    cipher, text_hash = encrypt_text(secret_text, password)
    combo = cipher + "|" + text_hash
    bits = text_to_binary(combo)
    dna_body = binary_to_dna(bits)

    # length header for body
    length_bits = format(len(dna_body), "032b")
    header_dna = binary_to_dna(length_bits)
    full_dna = header_dna + dna_body

    gc = gc_content(dna_body)
    print(f"[INFO] GC content of DNA payload: {gc:.2f}%")

    return full_dna

# ================== LSB EMBED / EXTRACT ==================

def embed_dna_in_image(cover_path: str, dna_payload: str, out_path: str = "stego_image.png"):
    img = Image.open(cover_path).convert("RGB")
    pixels = np.array(img)

    dna_bits = dna_to_binary(dna_payload)
    total_bits = len(dna_bits)
    capacity = pixels.size   # 1 bit per channel

    if total_bits > capacity:
        raise ValueError(f"Message too large. Need {total_bits} bits, have {capacity} bits.")

    flat = pixels.reshape(-1)
    for i in range(total_bits):
        bit = int(dna_bits[i])
        flat[i] = (flat[i] & 0b11111110) | bit

    stego_pixels = flat.reshape(pixels.shape)
    stego_img = Image.fromarray(stego_pixels.astype(np.uint8))
    stego_img.save(out_path)
    print(f"[OK] Stego image saved as {out_path} (used {total_bits}/{capacity} bits)")

def extract_dna_from_image(stego_path: str) -> str:
    img = Image.open(stego_path).convert("RGB")
    pixels = np.array(img)
    flat = pixels.reshape(-1)

    max_bits = flat.size
    max_bases = max_bits // 2

    # --- read header ---
    if HEADER_BITS > max_bits:
        raise ValueError("Image too small or not a valid stego image.")

    bits = "".join(str(flat[i] & 1) for i in range(HEADER_BITS))
    header_dna = binary_to_dna(bits)
    length_bits = dna_to_binary(header_dna)
    dna_len = int(length_bits, 2)

    # sanity check
    if dna_len <= 0 or HEADER_BASES + dna_len > max_bases:
        raise ValueError("Invalid length header (possible tampering).")

    total_bases = HEADER_BASES + dna_len
    total_bits_needed = total_bases * 2

    bits = "".join(str(flat[i] & 1) for i in range(total_bits_needed))
    full_dna = binary_to_dna(bits)
    return full_dna

# ================== ENCODE / DECODE FLOWS ==================

def encode_flow():
    cover = input("Cover image filename: ").strip()
    while not os.path.exists(cover):
        print("File not found.")
        cover = input("Cover image filename: ").strip()

    secret = input("Enter secret text: ")
    password = input("Enter password: ")

    dna_payload = build_dna_payload(secret, password)
    embed_dna_in_image(cover, dna_payload, "stego_image.png")

def decode_flow():
    stego = input("Stego image filename: ").strip()
    password = input("Enter password: ")

    try:
        full_dna = extract_dna_from_image(stego)
    except Exception as e:
        print("Not a valid stego image or data corrupted:", e)
        return

    # split header + body
    header_dna = full_dna[:HEADER_BASES]
    body_dna   = full_dna[HEADER_BASES:]

    bits = dna_to_binary(body_dna)
    combo = binary_to_text(bits)

    # split cipher | hash
    try:
        cipher, stored_hash = combo.split("|", 1)
    except ValueError:
        print("Data structure invalid (likely tampered).")
        return

    # decrypt with password
    try:
        plain = decrypt_text(cipher, password)
    except Exception:
        print("Access Denied (wrong password or heavily corrupted cipher).")
        return

    # hash check
    recomputed = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    if recomputed != stored_hash:
        print("Data Tampered (hash mismatch).")
    else:
        print("Secret Verified!")
        print("Recovered Message:\n", plain)

# ================== SIMPLE MENU ==================

def main():
    while True:
        print("\n=== DNA Image Steganography ===")
        print("1. Encode secret into image")
        print("2. Decode secret from image")
        print("3. Exit")
        choice = input("Choose option (1/2/3): ").strip()

        if choice == "1":
            encode_flow()
        elif choice == "2":
            decode_flow()
        elif choice == "3":
            print("Bye!")
            break
        else:
            print("Invalid choice. Try again.")

# Run in notebook / script
if __name__ == "__main__":
    main()

