import sys
import argparse
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# The order of the secp256r1 (NIST P-256) curve:
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=101
# just transformed the integer n to hex
# group_order will be available on cryptography 45.0.0
SECP256R1_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6BAAEDCE6AF48A03BBFD25E8CD036", 16
)


def generate_comment():
    """
    Generate a comment for the SSH key.
    """
    user = os.getenv("USER", "unknown_user")
    hostname = os.getenv("HOSTNAME", "unknown_host")
    return f"{user}@{hostname}"

def derive_ecdsa_private_key_from_seed(seed):
    """
    Derive a deterministic ECDSA private key object (on secp256r1) from a given seed.
    Returns a cryptography 'EllipticCurvePrivateKey' object.
    """
    # Convert seed to bytes if it's a string
    if isinstance(seed, str):
        seed_bytes = seed.encode("utf-8")
    else:
        seed_bytes = seed

    # 1. Hash the seed to get 256 bits
    digest = hashlib.sha256(seed_bytes).digest()
    # 2. Convert to integer
    priv_int = int.from_bytes(digest, "big")
    # 3. Force it into the valid range [1, order-1]
    priv_int_mod = (priv_int % (SECP256R1_ORDER - 1)) + 1

    # 4. Create a private key object from that integer
    private_key = ec.derive_private_key(priv_int_mod, ec.SECP256R1())
    return private_key


def export_private_key_openssh(private_key):
    """
    Export the ECDSA private key in a PEM format that OpenSSH can use.
    For modern versions of OpenSSH (>= 7.8), PKCS#8 is supported.
    Returns the key in PEM bytes.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_public_key_openssh(private_key, comment):
    """
    Export the corresponding ECDSA public key in the SSH authorized_keys format,
    e.g. 'ecdsa-sha2-nistp256 AAAAB3NzaC1lZDI1NTE5....'
    """
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    # pub_bytes is something like b'ecdsa-sha2-nistp256 AAAAB3NzaC1...'
    return pub_bytes + b" " + comment.encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate an ECDSA key pair from a seed.",
        prog="ssh_key_gen.py",
    )

    parser.add_argument(
        "--seed",
        type=str,
        default="")
    
    parser.add_argument(
        "--comment",
        type=str,
        default="")
    
    args = parser.parse_args()

    seed = args.seed

    if not seed:
        print("Please provide a seed with --seed argument.")
        sys.exit(1)
    

    comment = args.comment

    if not comment:
        comment = generate_comment()

    private_key_name = "id_ecdsa"
    public_key_name = "id_ecdsa.pub"

    # 1. Derive the private key
    priv_key = derive_ecdsa_private_key_from_seed(seed)

    # 2. Export private key (PEM, PKCS#8)
    private_key_pem = export_private_key_openssh(priv_key)

    # 3. Export public key (OpenSSH format)
    public_key_ssh = export_public_key_openssh(priv_key, comment)

    print("=== Private Key (PEM, PKCS#8) ===")
    print(private_key_pem.decode())

    print("=== Public Key (OpenSSH) ===")
    print(public_key_ssh.decode())

    # write to files. Maybe it should be controlled by arguments
    # add permission 0600 to private_key.pem
    with open(private_key_name, "wb") as f:
        f.write(private_key_pem)
    # set permission to 0600 (octal)  - read and write only for owner
    os.chmod(private_key_name, 0o600)

    with open(public_key_name, "wb") as f:
        f.write(public_key_ssh)