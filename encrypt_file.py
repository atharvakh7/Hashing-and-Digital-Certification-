import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt file with AES + RSA + Signature")
    parser.add_argument("--infile", required=True, help="Input plaintext file")
    parser.add_argument("--outfile", required=True, help="Output encrypted file")
    parser.add_argument("--keyfile", required=True, help="Wrapped AES key file")
    parser.add_argument("--sigfile", required=True, help="Digital signature file")
    parser.add_argument("--hashfile", required=True, help="Hash file")
    parser.add_argument("--sender-priv", required=True, help="Sender private key")
    parser.add_argument("--receiver-pub", required=True, help="Receiver public key")
    args = parser.parse_args()
    with open(args.infile, "rb") as f:
        plaintext = f.read()
    aes_key = os.urandom(32)
    ciphertext = encrypt_aes(plaintext, aes_key)
    with open(args.outfile, "wb") as f:
        f.write(ciphertext)
    with open(args.receiver_pub, "rb") as f:
        receiver_public = serialization.load_pem_public_key(f.read(), backend=default_backend())
    wrapped_key = receiver_public.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    with open(args.keyfile, "wb") as f:
        f.write(wrapped_key)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(plaintext)
    file_hash = digest.finalize()
    with open(args.hashfile, "wb") as f:
        f.write(file_hash)
    with open(args.sender_priv, "rb") as f:
        sender_private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    signature = sender_private.sign(
        file_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open(args.sigfile, "wb") as f:
        f.write(signature)
    print("[+] Encryption complete!")
    print(f"    Ciphertext: {args.outfile}")
    print(f"    Wrapped key: {args.keyfile}")
    print(f"    Hash: {args.hashfile}")
    print(f"    Signature: {args.sigfile}")