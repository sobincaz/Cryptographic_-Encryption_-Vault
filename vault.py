
import os
import json
import hashlib
import argparse
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuration
MAGIC = b"PYVAULT1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600000
EXTENSION = ".vault"


# Generate encryption key from master password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))


# Calculate SHA256 checksum
def checksum(data):
    return hashlib.sha256(data).hexdigest()


# Encrypt a single file
def encrypt_file(file_path, output_path, password):
    with open(file_path, "rb") as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = generate_key(password, salt)
    aes = AESGCM(key)

    header = MAGIC + salt + nonce

    encrypted_data = aes.encrypt(
        nonce,
        data,
        header
    )

    output_path.parent.mkdir(
        parents=True, exist_ok=True
    )

    if output_path.exists():
        raise FileExistsError(output_path)

    with open(output_path, "xb") as f:
        f.write(header + encrypted_data)

    return checksum(data)


# Decrypt a single file
def decrypt_file(file_path, output_path, password):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE

    if len(encrypted_data) < header_size + 16:
        raise ValueError("Invalid encrypted file")

    header = encrypted_data[:header_size]

    if not header.startswith(MAGIC):
        raise ValueError("Invalid vault format")

    offset = len(MAGIC)

    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = encrypted_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = encrypted_data[offset:]

    key = generate_key(password, salt)
    aes = AESGCM(key)

    # Authentication failure raises InvalidTag
    decrypted_data = aes.decrypt(
        nonce,
        ciphertext,
        header
    )

    output_path.parent.mkdir(
        parents=True, exist_ok=True
    )

    if output_path.exists():
        raise FileExistsError(output_path)

    with open(output_path, "xb") as f:
        f.write(decrypted_data)

    return checksum(decrypted_data)


# Encrypt entire directory
def encrypt_directory(source, destination, password, backup):
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    backup = Path(backup).resolve()

    if not source.is_dir():
        raise ValueError("Source directory does not exist")

    if source == destination:
        raise ValueError("Source and destination must differ")

    if source in destination.parents or destination in source.parents:
        raise ValueError("Source and destination cannot overlap")

    if source == backup or source in backup.parents:
        raise ValueError("Backup must be outside source directory")

    if destination == backup or destination in backup.parents:
        raise ValueError("Backup must be separate from destination")

    if backup.exists() and any(backup.iterdir()):
        raise FileExistsError("Backup directory must be empty")

    destination.mkdir(parents=True, exist_ok=True)

    manifest = []

    files = sorted(source.rglob("*"))

    for file_path in files:
        if file_path.is_symlink() or not file_path.is_file():
            continue

        relative = file_path.relative_to(source)
        encrypted_relative = Path(str(relative) + EXTENSION)

        output = destination / encrypted_relative

        digest = encrypt_file(
            file_path,
            output,
            password
        )

        manifest.append({
            "file": relative.as_posix(),
            "encrypted_file": encrypted_relative.as_posix(),
            "sha256": digest
        })

        print("[ENCRYPTED]", relative)

    backup.mkdir(parents=True, exist_ok=True)

    metadata = {
        "algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "files": manifest
    }

    with open(backup / "vault_metadata.json", "x") as f:
        json.dump(metadata, f, indent=4)

    print("\nDirectory encryption completed!")
    print("Total files encrypted:", len(manifest))


# Decrypt entire directory
def decrypt_directory(source, destination, password):
    source = Path(source).resolve()
    destination = Path(destination).resolve()

    if not source.is_dir():
        raise ValueError("Encrypted directory not found")

    if source == destination:
        raise ValueError("Source and destination must differ")

    if source in destination.parents or destination in source.parents:
        raise ValueError("Source and destination cannot overlap")

    encrypted_files = sorted(
        source.rglob("*" + EXTENSION)
    )

    if not encrypted_files:
        raise ValueError("No encrypted files found")

    destination.mkdir(parents=True, exist_ok=True)

    count = 0

    for file_path in encrypted_files:
        if file_path.is_symlink() or not file_path.is_file():
            continue

        relative = file_path.relative_to(source)

        original_name = str(relative)[:-len(EXTENSION)]
        output = destination / original_name

        digest = decrypt_file(
            file_path,
            output,
            password
        )

        print("[RESTORED]", original_name)
        print("SHA256:", digest)

        count += 1

    print("\nDirectory restoration completed!")
    print("Total files restored:", count)


# Main menu
def main():
    parser = argparse.ArgumentParser(
        description="Cryptographic Encryption Vault"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("source")
    encrypt_parser.add_argument("destination")
    encrypt_parser.add_argument("--backup", default="backup")

    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("source")
    decrypt_parser.add_argument("destination")

    args = parser.parse_args()

    password = getpass("Enter master password: ")

    try:
        if args.command == "encrypt":
            confirm = getpass("Confirm master password: ")

            if password != confirm:
                raise ValueError("Passwords do not match")

            encrypt_directory(
                args.source,
                args.destination,
                password,
                args.backup
            )

        elif args.command == "decrypt":
            decrypt_directory(
                args.source,
                args.destination,
                password
            )

    except Exception as error:
        print("\nERROR:", error)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
