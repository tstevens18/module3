
"""
Module for RSA key generation, digital signing, and verification of strings and files.
"""

import sys
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Key file names
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"


def generate_keys(private_path=PRIVATE_KEY_PATH, public_path=PUBLIC_KEY_PATH, key_size=2048):
    """
    Generate an RSA key pair and save to PEM files.

    Args:
        private_path (str): Path to save the private key.
        public_path (str): Path to save the public key.
        key_size (int): Size of the RSA key in bits (default 2048).
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    # Serialize private key (PEM, unencrypted for simplicity)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_path, "wb") as f:
        f.write(priv_pem)
    # Serialize public key (PEM)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pub_pem)
    print(f"Generated keys:\n  Private: {private_path}\n  Public:  {public_path}")


def load_private_key(path=PRIVATE_KEY_PATH):
    """
    Load an RSA private key from a PEM file.

    Args:
        path (str): Path to the private key file.

    Returns:
        RSAPrivateKey: The loaded private key object.
    """
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path=PUBLIC_KEY_PATH):
    """
    Load an RSA public key from a PEM file.

    Args:
        path (str): Path to the public key file.

    Returns:
        RSAPublicKey: The loaded public key object.
    """
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data)


def sign_bytes(private_key, data_bytes):
    """
    Sign bytes using RSA-PSS + SHA256. Returns raw signature bytes.
    """
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_bytes(public_key, data_bytes, signature_bytes):
    """
    Verify signature; returns True if valid, False if invalid.
    """
    try:
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def sign_string(text):
    """
    Sign a string using the private key and return base64-encoded signature.

    Args:
        text (str): The string to sign.

    Returns:
        str: Base64-encoded signature.

    Raises:
        FileNotFoundError: If private key file is missing.
    """
    if not Path(PRIVATE_KEY_PATH).exists():
        raise FileNotFoundError("Private key not found. Run the script with 'genkeys' first or generate keys.")
    priv = load_private_key()
    sig = sign_bytes(priv, text.encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")


def verify_string(text, b64_signature):
    """
    Verify a string signature using the public key.

    Args:
        text (str): The original string.
        b64_signature (str): Base64-encoded signature.

    Returns:
        bool: True if signature is valid, False otherwise.

    Raises:
        FileNotFoundError: If public key file is missing.
    """
    if not Path(PUBLIC_KEY_PATH).exists():
        raise FileNotFoundError("Public key not found. Run the script with 'genkeys' first or generate keys.")
    pub = load_public_key()
    sig = base64.b64decode(b64_signature)
    return verify_bytes(pub, text.encode("utf-8"), sig)


def sign_file(path):
    """
    Sign a file using the private key and return base64-encoded signature.

    Args:
        path (str): Path to the file to sign.

    Returns:
        str: Base64-encoded signature.

    Raises:
        FileNotFoundError: If file or private key is missing.
    """
    if not Path(path).is_file():
        raise FileNotFoundError(f"File not found: {path}")
    if not Path(PRIVATE_KEY_PATH).exists():
        raise FileNotFoundError("Private key not found. Run the script with 'genkeys' first or generate keys.")
    with open(path, "rb") as f:
        data = f.read()
    priv = load_private_key()
    sig = sign_bytes(priv, data)
    return base64.b64encode(sig).decode("ascii")


def verify_file(path, b64_signature):
    """
    Verify a file signature using the public key.

    Args:
        path (str): Path to the file to verify.
        b64_signature (str): Base64-encoded signature.

    Returns:
        bool: True if signature is valid, False otherwise.

    Raises:
        FileNotFoundError: If file or public key is missing.
    """
    if not Path(path).is_file():
        raise FileNotFoundError(f"File not found: {path}")
    if not Path(PUBLIC_KEY_PATH).exists():
        raise FileNotFoundError("Public key not found. Run the script with 'genkeys' first or generate keys.")
    with open(path, "rb") as f:
        data = f.read()
    pub = load_public_key()
    sig = base64.b64decode(b64_signature)
    return verify_bytes(pub, data, sig)


def demo():
    """
    Run a demonstration of signing and verifying strings and files.
    """
    print("=== Sign / Verify Demo (using cryptography library) ===")
    # Generate keys if missing
    if not (Path(PRIVATE_KEY_PATH).exists() and Path(PUBLIC_KEY_PATH).exists()):
        print("Keys not found — generating a new RSA key pair...")
        generate_keys()
    else:
        print(f"Using existing keys: {PRIVATE_KEY_PATH}, {PUBLIC_KEY_PATH}")

    # Demo string signing
    msg = "Hello, this is a test message."
    print("\n-- String signing demo --")
    print("Message:", msg)
    sig_b64 = sign_string(msg)
    print("Signature (base64):", sig_b64)
    ok = verify_string(msg, sig_b64)
    print("Verification result:", "VALID" if ok else "INVALID")

    # Demo file signing
    sample_file = "sample.txt"
    print("\n-- File signing demo --")
    # create a small sample file
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write("Sample file contents for signing.\n")
    print("Created sample file:", sample_file)
    file_sig = sign_file(sample_file)
    print("File signature (base64):", file_sig)
    ok2 = verify_file(sample_file, file_sig)
    print("File verification result:", "VALID" if ok2 else "INVALID")
    print("\nDemo complete. You can reuse private_key.pem and public_key.pem for further signing/verifying.")


def usage_and_exit():
    """
    Print usage information and exit.
    """
    print(__doc__)
    sys.exit(0)


def main():
    """
    Main entry point for the command-line interface.
    """
    if len(sys.argv) == 1:
        demo()
        return

    cmd = sys.argv[1].lower()

    try:
        if cmd == "genkeys":
            generate_keys()
        elif cmd == "signstr" and len(sys.argv) >= 3:
            text = sys.argv[2]
            print(sign_string(text))
        elif cmd == "verifystr" and len(sys.argv) >= 4:
            text = sys.argv[2]
            sig = sys.argv[3]
            print("VALID" if verify_string(text, sig) else "INVALID")
        elif cmd == "signfile" and len(sys.argv) >= 3:
            path = sys.argv[2]
            print(sign_file(path))
        elif cmd == "verifyfile" and len(sys.argv) >= 4:
            path = sys.argv[2]
            sig = sys.argv[3]
            print("VALID" if verify_file(path, sig) else "INVALID")
        else:
            usage_and_exit()
    except FileNotFoundError as e:
        print("Error:", e)
        sys.exit(2)
    except Exception as e:
        print("Unexpected error:", e)
        sys.exit(3)


if __name__ == "__main__":
    main()
