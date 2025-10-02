#!/usr/bin/env python3
"""
MyFS: A secure cloud-based virtual file system with AES encryption, TOTP authentication,
machine-bound access, and recoverable/permanent deletion.
Structure:
- MyFSCore: contains low-level logic (encryption, I/O, metadata)
- MyFSCLI : provides a simple console interface for the user
"""

import os
import sys
import json
import uuid
import socket
import hashlib
import getpass
import pyotp
import qrcode
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
HEADER_SIZE = int(os.getenv('HEADER_SIZE', 512))
METADATA_ENTRY_SIZE = int(os.getenv('METADATA_ENTRY_SIZE', 512))
MAX_FILES = int(os.getenv('MAX_FILES', 100))
TOTAL_METADATA_SIZE = int(os.getenv('TOTAL_METADATA_SIZE', 51200)) 
MAGIC_DRI = os.getenv('MAGIC_DRI', 'MYFS').encode()  
MAGIC_KEY = os.getenv('MAGIC_KEY', 'MKEY').encode()  
VERSION_BYTES = int(os.getenv('VERSION_BYTES', 1)).to_bytes(4, 'big')
EMBEDDED_HASH = os.getenv('EMBEDDED_HASH')  

def compute_machine_id() -> bytes:
    """
    Compute a 16-byte machine identifier based on hostname and MAC address.
    This binds the volume to a specific machine.
    """
    hostname_bytes = socket.gethostname().encode('utf-8')
    mac_bytes = hex(uuid.getnode()).encode('utf-8')
    digest = hashlib.sha256(hostname_bytes + b"-" + mac_bytes).digest()
    return digest[:16]  # Take first 16 bytes


def self_check_integrity():
    """
    Verify this script's own SHA256 hash against an embedded constant.
    If mismatch, exit immediately (possible tampering).
    """
    try:
        script_path = os.path.abspath(__file__)
        with open(script_path, 'rb') as f:
            content = f.read()
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != EMBEDDED_HASH:
            print("❌ Code integrity verification failed! Exiting to prevent tampering.")
            sys.exit(1)
    except Exception:
        print("⚠️ Unable to verify self integrity. Continuing with caution.")


class MyFSCore:
    """
    Core engine for MyFS:
    - Manipulates MyFS.DRI (data storage) and MyFS.KEY (encrypted metadata)
    - Provides methods for creating, mounting, reading, writing, deleting, and recovering files
    - Handles AES-256-CFB encryption/decryption, TOTP, machine ID check, metadata management
    """

    def __init__(self):
        self.dri_filename = "MyFS.DRI"
        self.key_filename = "MyFS.KEY"
        self.totp_secret = None
        self.metadata = None
        self.cloud_path = None
        self.removable_path = None

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive a 32-byte AES key from the given password and salt using PBKDF2-HMAC-SHA256.
        """
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return kdf[:32]

    def create_volume(self, cloud_path: str, removable_path: str, volume_password: str):
        """
        Create and format a new MyFS volume:
        - cloud_path: directory representing the "cloud disk"
        - removable_path: directory representing the "removable disk"
        - volume_password: user-chosen password to protect metadata
        """
        self.cloud_path = cloud_path
        self.removable_path = removable_path
        dri_path = os.path.join(cloud_path, self.dri_filename)
        key_path = os.path.join(removable_path, self.key_filename)

        # Prevent overwriting existing files
        if os.path.exists(dri_path) or os.path.exists(key_path):
            raise FileExistsError("MyFS files already exist in the specified locations.")

        # Generate random salt and derive volume encryption key
        salt = os.urandom(16)
        vol_key = self.derive_key(volume_password, salt)

        # Build DRI header: MAGIC + VERSION + MachineID + padding to 512 bytes
        machine_id = compute_machine_id()
        header_dri = MAGIC_DRI + VERSION_BYTES + machine_id
        header_dri = header_dri.ljust(HEADER_SIZE, b'\x00')

        # Generate TOTP secret and QR code for two-factor authentication
        self.totp_secret = pyotp.random_base32(32)
        totp_uri = pyotp.TOTP(self.totp_secret).provisioning_uri(
            name="MyFS@User", issuer_name="MyFS System"
        )
        qr_img = qrcode.make(totp_uri)
        qr_img.save("myfs_qr.png")
        print(f"🔐 TOTP Secret: {self.totp_secret}")
        print("📷 QR code saved as 'myfs_qr.png'. Scan it with Google Authenticator.")

        # Prepare initial metadata structure
        now_iso = datetime.now().isoformat()
        self.metadata = {
            "files": [],
            "totp_secret": self.totp_secret,
            "created_at": now_iso,
            "last_modified": now_iso
        }
        metadata_json = json.dumps(self.metadata).encode('utf-8')

        # Encrypt metadata JSON using AES-CFB with volume key
        iv_meta = os.urandom(16)
        cipher_meta = Cipher(algorithms.AES(vol_key), modes.CFB(iv_meta), backend=default_backend())
        encryptor_meta = cipher_meta.encryptor()
        encrypted_metadata = iv_meta + encryptor_meta.update(metadata_json) + encryptor_meta.finalize()

        # Compute hash of DRI header
        dri_hash = hashlib.sha256(header_dri).digest()

        # Build KEY header: MAGIC + VERSION + hash(DRI header) + salt, padded to 512 bytes
        header_key = MAGIC_KEY + VERSION_BYTES + dri_hash + salt
        header_key = header_key.ljust(HEADER_SIZE, b'\x00')

        # Write MyFS.DRI: header + reserved metadata area (zeros)
        with open(dri_path, 'wb') as dri_f:
            dri_f.write(header_dri)
            dri_f.write(b'\x00' * TOTAL_METADATA_SIZE)  # Reserve space for metadata if needed later

        # Write MyFS.KEY: header + encrypted metadata
        with open(key_path, 'wb') as key_f:
            key_f.write(header_key)
            key_f.write(encrypted_metadata)

        print("✅ MyFS volume created successfully!")

    def mount_volume(self, cloud_path: str, removable_path: str, volume_password: str):
        """
        Mount an existing MyFS volume:
        - Verifies the KEY header, DRI integrity, machine ID, and TOTP
        - Loads decrypted metadata into self.metadata
        - Returns True if successful; raises exceptions otherwise
        """
        self.cloud_path = cloud_path
        self.removable_path = removable_path
        dri_path = os.path.join(cloud_path, self.dri_filename)
        key_path = os.path.join(removable_path, self.key_filename)

        # Both files must exist
        if not (os.path.exists(dri_path) and os.path.exists(key_path)):
            raise FileNotFoundError("Missing MyFS.DRI or MyFS.KEY. Cannot mount.")

        # Read and validate KEY header
        with open(key_path, 'rb') as key_f:
            header_key = key_f.read(HEADER_SIZE)
            if header_key[:4] != MAGIC_KEY:
                raise ValueError("Invalid MyFS.KEY file format.")

            # Extract stored DRI hash and salt from KEY header
            stored_dri_hash = header_key[8:40]
            salt = header_key[40:56]
            encrypted_metadata = key_f.read()  # remainder is encrypted metadata

        # Read and check DRI header
        with open(dri_path, 'rb') as dri_f:
            header_dri = dri_f.read(HEADER_SIZE)
            actual_dri_hash = hashlib.sha256(header_dri).digest()
            if actual_dri_hash != stored_dri_hash:
                raise ValueError("DRI file integrity check failed (hash mismatch).")

            # Check if DRI was created on this machine
            stored_machine_id = header_dri[8:24]
            current_machine_id = compute_machine_id()
            if stored_machine_id != current_machine_id:
                raise PermissionError("⛔ MyFS.DRI was not created on this machine.")

        # Derive volume key and decrypt metadata
        vol_key = self.derive_key(volume_password, salt)
        iv_meta = encrypted_metadata[:16]
        cipher_meta = Cipher(algorithms.AES(vol_key), modes.CFB(iv_meta), backend=default_backend())
        decryptor_meta = cipher_meta.decryptor()
        try:
            decrypted_json = decryptor_meta.update(encrypted_metadata[16:]) + decryptor_meta.finalize()
            self.metadata = json.loads(decrypted_json)
        except Exception:
            raise ValueError("Volume password incorrect or metadata corrupted.")

        # Verify TOTP code
        totp = pyotp.TOTP(self.metadata["totp_secret"])
        user_code = input("➡️ Enter TOTP code from Google Authenticator: ").strip()
        if not totp.verify(user_code):
            raise ValueError("❌ Invalid TOTP code. Mount aborted.")

        print("🔓 MyFS volume mounted successfully!")
        return True

    def list_files(self, show_deleted: bool = False) -> list:
        """
        List names of files currently in the volume.
        If show_deleted=False, omit logically deleted files.
        """
        return [
            entry["name"]
            for entry in self.metadata["files"]
            if show_deleted or not entry.get("deleted", False)
        ]

    def list_deleted_files(self) -> list:
        """
        Return a list of file names that are marked as logically deleted.
        """
        return [entry["name"] for entry in self.metadata["files"] if entry.get("deleted", False)]

    def _locate_free_offset(self) -> int:
        """
        Scan MyFS.DRI to find a free block (≥ 1 KB of 0x00) after the metadata area.
        If none found, return EOF (append mode).
        """
        dri_path = os.path.join(self.cloud_path, self.dri_filename)
        start_offset = HEADER_SIZE + TOTAL_METADATA_SIZE
        with open(dri_path, 'rb') as dri_f:
            dri_f.seek(start_offset)
            data = dri_f.read()

        index = data.find(b'\x00' * 1024)
        if index != -1:
            return start_offset + index
        else:
            return start_offset + len(data)

    def _persist_metadata(self, volume_password: str):
        """
        Encrypt the current metadata JSON and write it back to MyFS.KEY (overwriting old encrypted data).
        """
        key_path = os.path.join(self.removable_path, self.key_filename)
        # Re-derive volume key
        with open(key_path, 'rb+') as key_f:
            header_key = key_f.read(HEADER_SIZE)
            salt = header_key[40:56]
            vol_key = self.derive_key(volume_password, salt)

            # Prepare new encrypted metadata
            self.metadata["last_modified"] = datetime.now().isoformat()
            metadata_json = json.dumps(self.metadata).encode('utf-8')
            iv_meta = os.urandom(16)
            cipher_meta = Cipher(algorithms.AES(vol_key), modes.CFB(iv_meta), backend=default_backend())
            encryptor_meta = cipher_meta.encryptor()
            encrypted_payload = iv_meta + encryptor_meta.update(metadata_json) + encryptor_meta.finalize()

            # Overwrite: truncate file to HEADER_SIZE, then append new encrypted metadata
            key_f.seek(0)
            key_f.truncate(HEADER_SIZE)
            key_f.seek(HEADER_SIZE)
            key_f.write(encrypted_payload)

    def add_file(self, source_path: str, name_in_fs: str, volume_password: str, file_password: str):
        """
        Import a file from local system into the MyFS volume:
        - Verifies source exists, name_in_fs not duplicated.
        - Encrypts file content with file_password (AES-CFB).
        - Finds a free block in DRI, writes encrypted data.
        - Updates metadata with file entry (original_path + block info).
        """
        dri_path = os.path.join(self.cloud_path, self.dri_filename)
        key_path = os.path.join(self.removable_path, self.key_filename)

        # Prevent duplicate names
        if any(e["name"] == name_in_fs for e in self.metadata["files"]):
            raise FileExistsError(f"File '{name_in_fs}' already exists in MyFS.")

        # Ensure source file exists
        if not os.path.isfile(source_path):
            raise FileNotFoundError(f"Source file '{source_path}' not found.")

        # Read raw file data
        with open(source_path, 'rb') as src_f:
            raw_data = src_f.read()

        # Extract salt from KEY header to derive file key
        with open(key_path, 'rb') as key_f:
            key_hdr = key_f.read(HEADER_SIZE)
            salt = key_hdr[40:56]

        # Derive and encrypt file data
        file_key = self.derive_key(file_password, salt)
        iv_file = os.urandom(16)
        cipher_file = Cipher(algorithms.AES(file_key), modes.CFB(iv_file), backend=default_backend())
        encryptor_file = cipher_file.encryptor()
        encrypted_payload = iv_file + encryptor_file.update(raw_data) + encryptor_file.finalize()

        # Find offset in DRI to write encrypted payload
        offset = self._locate_free_offset()
        with open(dri_path, 'r+b') as dri_f:
            dri_f.seek(offset)
            dri_f.write(encrypted_payload)

        # Build metadata entry
        now_iso = datetime.now().isoformat()
        entry = {
            "name": name_in_fs,
            "size": len(raw_data),
            "created_at": now_iso,
            "modified_at": now_iso,
            "original_path": source_path,
            "blocks": [{
                "offset": offset,
                "size": len(encrypted_payload),
                "iv": iv_file.hex()
            }]
        }
        self.metadata["files"].append(entry)

        # Persist metadata back to KEY file
        self._persist_metadata(volume_password)

        print(f"✅ File '{name_in_fs}' added successfully!")

    def export_file(self, name_in_fs: str, destination_path: str, file_password: str):
        """
        Export/decrypt a file from MyFS volume to a local destination:
        - Finds file entry, reads encrypted data from DRI, decrypts using file_password,
          then writes plaintext to destination_path.
        """
        dri_path = os.path.join(self.cloud_path, self.dri_filename)
        key_path = os.path.join(self.removable_path, self.key_filename)

        # Locate entry
        entry = next((e for e in self.metadata["files"] if e["name"] == name_in_fs), None)
        if entry is None:
            raise FileNotFoundError(f"File '{name_in_fs}' not found in MyFS.")

        block = entry["blocks"][0]
        offset = block["offset"]
        size_enc = block["size"]
        iv_file = bytes.fromhex(block["iv"])

        # Read encrypted data
        with open(dri_path, 'rb') as dri_f:
            dri_f.seek(offset)
            encrypted_data = dri_f.read(size_enc)

        # Derive key from file_password
        with open(key_path, 'rb') as key_f:
            key_hdr = key_f.read(HEADER_SIZE)
            salt = key_hdr[40:56]
        file_key = self.derive_key(file_password, salt)

        # Decrypt and write to destination
        cipher_file = Cipher(algorithms.AES(file_key), modes.CFB(iv_file), backend=default_backend())
        decryptor_file = cipher_file.decryptor()
        decrypted_data = decryptor_file.update(encrypted_data[16:]) + decryptor_file.finalize()

        with open(destination_path, 'wb') as out_f:
            out_f.write(decrypted_data)

        print(f"📤 File '{name_in_fs}' exported to '{destination_path}'.")

    def change_file_password(self, name_in_fs: str, old_file_password: str, new_file_password: str, volume_password: str):
        """
        Change the AES password for a given file in the volume:
        - Decrypts the existing data with old_file_password, re-encrypts with new_file_password
        - Updates block.iv and block.size in metadata, persists metadata.
        """
        dri_path = os.path.join(self.cloud_path, self.dri_filename)
        key_path = os.path.join(self.removable_path, self.key_filename)

        # Locate entry
        entry = next((e for e in self.metadata["files"] if e["name"] == name_in_fs), None)
        if entry is None:
            raise FileNotFoundError(f"File '{name_in_fs}' not found in MyFS.")

        block = entry["blocks"][0]
        offset = block["offset"]
        size_enc = block["size"]
        iv_old = bytes.fromhex(block["iv"])

        # Read encrypted data
        with open(dri_path, 'rb') as dri_f:
            dri_f.seek(offset)
            encrypted_data = dri_f.read(size_enc)

        # Derive old key and decrypt
        with open(key_path, 'rb') as key_f:
            key_hdr = key_f.read(HEADER_SIZE)
            salt = key_hdr[40:56]
        old_key = self.derive_key(old_file_password, salt)
        cipher_old = Cipher(algorithms.AES(old_key), modes.CFB(iv_old), backend=default_backend())
        decryptor_old = cipher_old.decryptor()
        try:
            plaintext = decryptor_old.update(encrypted_data[16:]) + decryptor_old.finalize()
        except Exception:
            raise ValueError("❌ Old file password is incorrect or data is corrupted.")

        # Encrypt with new password
        new_key = self.derive_key(new_file_password, salt)
        iv_new = os.urandom(16)
        cipher_new = Cipher(algorithms.AES(new_key), modes.CFB(iv_new), backend=default_backend())
        encryptor_new = cipher_new.encryptor()
        new_encrypted_data = iv_new + encryptor_new.update(plaintext) + encryptor_new.finalize()

        # Overwrite the data region in DRI
        with open(dri_path, 'r+b') as dri_f:
            dri_f.seek(offset)
            dri_f.write(new_encrypted_data)

        # Update metadata
        block["iv"] = iv_new.hex()
        block["size"] = len(new_encrypted_data)
        entry["modified_at"] = datetime.now().isoformat()

        # Save updated metadata
        self._persist_metadata(volume_password)
        print(f"🔑 Password for file '{name_in_fs}' changed successfully.")

    def change_volume_password(self, old_volume_password: str, new_volume_password: str):
        """
        Change the password protecting the entire volume metadata:
        - Decrypts metadata with old password, re-encrypts with new password (same salt)
        - Updates KEY file accordingly
        """
        key_path = os.path.join(self.removable_path, self.key_filename)

        # Read existing encrypted metadata
        with open(key_path, 'rb+') as key_f:
            header_key = key_f.read(HEADER_SIZE)
            stored_dri_hash = header_key[8:40]
            salt = header_key[40:56]
            encrypted_metadata = key_f.read()

            # Derive old key and decrypt
            old_key = self.derive_key(old_volume_password, salt)
            iv_meta_old = encrypted_metadata[:16]
            cipher_meta_old = Cipher(algorithms.AES(old_key), modes.CFB(iv_meta_old), backend=default_backend())
            decryptor_meta_old = cipher_meta_old.decryptor()
            try:
                metadata_json = decryptor_meta_old.update(encrypted_metadata[16:]) + decryptor_meta_old.finalize()
            except Exception:
                raise ValueError("❌ Old volume password is incorrect.")

            # Derive new key (using same salt), encrypt with new IV
            iv_meta_new = os.urandom(16)
            new_key = self.derive_key(new_volume_password, salt)
            cipher_meta_new = Cipher(algorithms.AES(new_key), modes.CFB(iv_meta_new), backend=default_backend())
            encryptor_meta_new = cipher_meta_new.encryptor()
            new_encrypted_payload = iv_meta_new + encryptor_meta_new.update(metadata_json) + encryptor_meta_new.finalize()

            # Overwrite KEY file: header (unchanged except maybe salt), then new encrypted payload
            key_f.seek(0)
            # If you want to change salt, you'd generate a new salt here and recompute old_key/new_key accordingly.
            # For simplicity, keep the old salt.
            key_f.truncate(HEADER_SIZE)
            key_f.write(header_key)  # unchanged header
            key_f.write(new_encrypted_payload)

        print("🔑 Volume password changed successfully.")

    def delete_file(self, name_in_fs: str, volume_password: str, file_password: str, permanent: bool = False):
        """
        Delete a file in MyFS. Options:
        - permanent=False → logical delete (set 'deleted'=True)
        - permanent=True  → overwrite data region with zeros, remove entry
        """
        dri_path = os.path.join(self.cloud_path, self.dri_filename)
        key_path = os.path.join(self.removable_path, self.key_filename)

        # Find the entry
        entry = next((e for e in self.metadata["files"] if e["name"] == name_in_fs), None)
        if entry is None:
            raise FileNotFoundError(f"File '{name_in_fs}' not found in MyFS.")

        # Verify file password by attempting to decrypt
        block = entry["blocks"][0]
        offset = block["offset"]
        size_enc = block["size"]
        iv_file = bytes.fromhex(block["iv"])

        with open(dri_path, 'rb') as dri_f:
            dri_f.seek(offset)
            encrypted_data = dri_f.read(size_enc)

        with open(key_path, 'rb') as key_f:
            key_hdr = key_f.read(HEADER_SIZE)
            salt = key_hdr[40:56]
        file_key = self.derive_key(file_password, salt)
        cipher_file = Cipher(algorithms.AES(file_key), modes.CFB(iv_file), backend=default_backend())
        decryptor_file = cipher_file.decryptor()
        try:
            _ = decryptor_file.update(encrypted_data[16:]) + decryptor_file.finalize()
        except Exception:
            raise PermissionError("❌ File password incorrect. Cannot delete.")

        if permanent:
            # Overwrite data region with zeros
            with open(dri_path, 'r+b') as dri_f:
                dri_f.seek(offset)
                dri_f.write(b'\x00' * size_enc)
            self.metadata["files"].remove(entry)
            print(f"🗑️ File '{name_in_fs}' permanently deleted.")
        else:
            entry["deleted"] = True
            print(f"🚫 File '{name_in_fs}' marked as deleted (recoverable).")

        # Persist metadata changes
        self._persist_metadata(volume_password)

    def recover_file(self, name_in_fs: str, volume_password: str):
        """
        Recover a logically deleted file (remove 'deleted' flag in metadata).
        """
        # Locate entry with deleted=True
        entry = next((e for e in self.metadata["files"] if e["name"] == name_in_fs and e.get("deleted", False)), None)
        if entry is None:
            raise FileNotFoundError(f"File '{name_in_fs}' not in deleted list.")

        entry["deleted"] = False
        entry["modified_at"] = datetime.now().isoformat()
        self._persist_metadata(volume_password)
        print(f"✅ File '{name_in_fs}' recovered successfully.")


class MyFSCLI:
    """
    Console-based interface that interacts with MyFSCore.
    Presents a menu, handles user input, and calls core methods.
    """

    def __init__(self):
        self.core = MyFSCore()
        self.is_mounted = False
        self.cloud_path = None
        self.removable_path = None

    def print_menu(self):
        menu_text = """
        ==== MyFS MENU ====
        1. Create new MyFS volume
        2. Mount existing volume
        3. Add (import) file into volume
        4. List files in volume
        5. Change file password
        6. Change volume password
        7. Export file from volume
        8. Delete file in volume
        9. Recover deleted file
        0. Exit
        """
        print(menu_text)

    def run(self):
        """
        Main loop: prompt user for the two mount paths, then display menu indefinitely
        until the user chooses to exit.
        """
        print("🔧 Enter cloud disk path (e.g., F:): ", end='')
        self.cloud_path = input().strip()
        print("🔧 Enter removable disk path (e.g., G:): ", end='')
        self.removable_path = input().strip()

        while True:
            self.print_menu()
            choice = input("Select an option: ").strip()

            if choice == "1":
                # Create a new volume
                vol_pw = getpass.getpass("Enter new volume password: ")
                try:
                    self.core.create_volume(self.cloud_path, self.removable_path, vol_pw)
                except Exception as e:
                    print(f"❌ Error creating volume: {e}")

            elif choice == "2":
                # Mount existing volume
                if self.is_mounted:
                    print("✅ Volume already mounted.")
                else:
                    vol_pw = getpass.getpass("Enter volume password: ")
                    try:
                        success = self.core.mount_volume(self.cloud_path, self.removable_path, vol_pw)
                        if success:
                            self.is_mounted = True
                        else:
                            print("❌ Mount failed.")
                    except Exception as e:
                        print(f"❌ {e}")

            elif choice == "3":
                # Import file
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                vol_pw = getpass.getpass("Enter volume password: ")
                src = input("Enter source file path: ").strip()
                name_fs = input("Enter name to store in MyFS: ").strip()
                file_pw = getpass.getpass("Enter file password: ")
                try:
                    self.core.add_file(src, name_fs, vol_pw, file_pw)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "4":
                # List files
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                print("Show deleted files? 1-No  2-Yes  3-Both")
                sub = input("Choice: ").strip()
                if sub == "1":
                    files = self.core.list_files(show_deleted=False)
                elif sub == "2":
                    files = self.core.list_deleted_files()
                elif sub == "3":
                    files = self.core.list_files(show_deleted=True)
                else:
                    print("❗ Invalid selection.")
                    continue
                print("📄 Files:", files)

            elif choice == "5":
                # Change a file's password
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                fname = input("Filename to change password: ").strip()
                old_pw = getpass.getpass("Old file password: ")
                new_pw = getpass.getpass("New file password: ")
                vol_pw = getpass.getpass("Volume password: ")
                try:
                    self.core.change_file_password(fname, old_pw, new_pw, vol_pw)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "6":
                # Change volume password
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                old_vol = getpass.getpass("Old volume password: ")
                new_vol = getpass.getpass("New volume password: ")
                try:
                    self.core.change_volume_password(old_vol, new_vol)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "7":
                # Export file
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                vol_pw = getpass.getpass("Volume password: ")
                file_pw = getpass.getpass("File password: ")
                fname = input("Filename to export: ").strip()
                dest = input("Output file path (including name): ").strip()
                try:
                    self.core.export_file(fname, dest, file_pw)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "8":
                # Delete file
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                vol_pw = getpass.getpass("Volume password: ")
                fname = input("Filename to delete: ").strip()
                perm = input("Permanently delete? (y/n): ").strip().lower() == "y"
                file_pw = getpass.getpass("File password: ")
                try:
                    self.core.delete_file(fname, vol_pw, file_pw, permanent=perm)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "9":
                # Recover deleted file
                if not self.is_mounted:
                    print("⚠️ Please mount the volume first (option 2).")
                    continue
                vol_pw = getpass.getpass("Volume password: ")
                fname = input("Filename to recover: ").strip()
                try:
                    self.core.recover_file(fname, vol_pw)
                except Exception as e:
                    print(f"❌ {e}")

            elif choice == "0":
                print("👋 Goodbye!")
                sys.exit(0)

            else:
                print("❗ Invalid option. Please try again.")


if __name__ == "__main__":
    self_check_integrity()  # Optional: verify script integrity at startup
    cli = MyFSCLI()
    cli.run()
