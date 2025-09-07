from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import argparse

def generate_rsa_keys(name, key_size=2048):
    """Generate RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    os.makedirs("keys", exist_ok=True)

    with open(f"keys/{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"keys/{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[+] RSA keys generated for {name}:")
    print(f"    keys/{name}_private.pem")
    print(f"    keys/{name}_public.pem")

def generate_aes_key(size=32):
    """Generate AES symmetric key (default 256-bit)."""
    os.makedirs("data", exist_ok=True)

    key = os.urandom(size)
    with open("data/secret.key", "wb") as f:
        f.write(key)

    print(f"[+] AES key generated (size {size * 8} bits): data/secret.key")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate cryptographic keys")
    parser.add_argument("--name", help="Name prefix for RSA key files (e.g., sender or receiver)")
    parser.add_argument("--aes", action="store_true", help="Generate AES symmetric key instead of RSA keys")

    args = parser.parse_args()

    if args.aes:
        generate_aes_key()
    else:
        if not args.name:
            print("[-] Please provide --name for RSA key generation, or use --aes for AES key")
        else:
            generate_rsa_keys(args.name)
