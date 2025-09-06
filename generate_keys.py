from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import argparse

def generate_keys(name, key_size=2048):
    private_key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key=private_key.public_key()
    os.makedirs("keys",exist_ok=True)
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
    print(f"[+] Keys generated for {name}:")
    print(f"    keys/{name}_private.pem")
    print(f"    keys/{name}_public.pem")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA key pairs")
    parser.add_argument("--name", required=True, help="Name prefix for the key files (e.g., sender or receiver)")
    args = parser.parse_args()

    generate_keys(args.name)