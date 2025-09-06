import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt file with AES + RSA + Signature Verification")
    parser.add_argument("--infile", required=True, help="Input encrypted file")
    parser.add_argument("--outfile", required=True, help="Output decrypted file")
    parser.add_argument("--keyfile", required=True, help="Wrapped AES key file")
    parser.add_argument("--sigfile", required=True, help="Digital signature file")
    parser.add_argument("--hashfile", required=True, help="Original hash file")
    parser.add_argument("--receiver-priv", required=True, help="Receiver private key")
    parser.add_argument("--sender-pub", required=True, help="Sender public key")
    args = parser.parse_args()
    with open(args.receiver_priv, "rb") as f:
        receiver_private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(args.keyfile, "rb") as f:
        wrapped_key = f.read()
    aes_key = receiver_private.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    with open(args.infile, "rb") as f:
        ciphertext = f.read()
    plaintext = decrypt_aes(ciphertext, aes_key)
    with open(args.outfile, "wb") as f:
        f.write(plaintext)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(plaintext)
    new_hash = digest.finalize()
    with open(args.hashfile, "rb") as f:
        original_hash = f.read()
    with open(args.sigfile, "rb") as f:
        signature = f.read()
    with open(args.sender_pub, "rb") as f:
        sender_public = serialization.load_pem_public_key(f.read(), backend=default_backend())
    try:
        sender_public.verify(
            signature,
            original_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        if new_hash == original_hash:
            print("[+] Verification successful: Integrity and authenticity confirmed!")
        else:
            print("[!] Hash mismatch: Integrity check failed.")
    except Exception as e:
        print("[!] Signature verification failed:", str(e))