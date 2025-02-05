import sys
import argparse
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_comment():
    """
    Generate a comment for the SSH key, e.g. "user@hostname".
    """
    user = os.getenv("USER", "unknown_user")
    hostname = os.getenv("HOSTNAME", "unknown_host")
    return f"{user}@{hostname}"


def derive_ed25519_private_key_from_seed(seed):
    """
    Derive a deterministic Ed25519 private key from a given seed (string or bytes).
    1. Convert to bytes if it's a string
    2. Hash with SHA-256 -> 32 bytes
    3. Create Ed25519PrivateKey from that 32-byte digest
    """
    if isinstance(seed, str):
        seed_bytes = seed.encode("utf-8")
    else:
        seed_bytes = seed

    # Hash the seed to get exactly 32 bytes
    digest = hashlib.sha256(seed_bytes).digest()  # 32 bytes
    # Create the Ed25519 private key from these 32 bytes
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(digest)
    return private_key


def export_private_key_openssh(private_key):
    """
    Export the Ed25519 private key in OpenSSH native format
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_public_key_openssh(private_key, comment):
    """
    Export the corresponding Ed25519 public key in the standard OpenSSH
    authorized_keys format: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...' plus a comment.
    """
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    # pub_bytes looks like b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...'
    return pub_bytes + b" " + comment.encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate an Ed25519 key pair from a seed.",
        prog="ssh_key_gen.py",
    )
    parser.add_argument(
        "--seed", type=str, default="", help="Seed for deterministic key generation."
    )
    parser.add_argument(
        "--comment", type=str, default="", help="Comment string for the public key."
    )

    args = parser.parse_args()

    seed = args.seed
    if not seed:
        print("Please provide a seed with --seed argument.")
        sys.exit(1)

    comment = args.comment
    if not comment:
        comment = generate_comment()

    private_key_name = "id_ed25519"
    public_key_name = "id_ed25519.pub"

    # 1. Derive the private key
    priv_key = derive_ed25519_private_key_from_seed(seed)

    # 2. Export private key (PEM, PKCS#8)
    private_key_pem = export_private_key_openssh(priv_key)

    # 3. Export public key (OpenSSH format)
    public_key_ssh = export_public_key_openssh(priv_key, comment)

    print("=== Private Key (PEM, PKCS#8) ===")
    print(private_key_pem.decode())

    print("=== Public Key (OpenSSH) ===")
    print(public_key_ssh.decode())

    # Write to files
    with open(private_key_name, "wb") as f:
        f.write(private_key_pem)
    # chmod 0600 (owner read/write only)
    os.chmod(private_key_name, 0o600)

    with open(public_key_name, "wb") as f:
        f.write(public_key_ssh)
