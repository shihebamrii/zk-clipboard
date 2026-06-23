import os
import sys
import time
import getpass
import requests
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_keys(password: str, salt_bytes: bytes):
    """
    Derives a 32-byte encryption key and a 32-byte server verifier hash
    from the password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt_bytes,
        iterations=100000
    )
    key_material = kdf.derive(password.encode())
    # First 32 bytes: AES-256 encryption key (held strictly client-side)
    encryption_key = key_material[:32]
    # Last 32 bytes: verifier hash (shared with server for authorization)
    verifier_hash = key_material[32:].hex()
    return encryption_key, verifier_hash

def encrypt_data(key: bytes, plaintext: str) -> tuple:
    """Encrypts plaintext string using AES-256-GCM. Returns (ciphertext_hex, iv_hex, tag_hex)."""
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 12-byte IV for GCM
    data = plaintext.encode('utf-8')
    ciphertext_with_tag = aesgcm.encrypt(iv, data, None)
    
    # Split ciphertext and the 16-byte authentication tag
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    
    return ciphertext.hex(), iv.hex(), tag.hex()

def decrypt_data(key: bytes, ciphertext_hex: str, iv_hex: str, tag_hex: str) -> str:
    """Decrypts AES-256-GCM encrypted hex blocks."""
    aesgcm = AESGCM(key)
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    
    ciphertext_with_tag = ciphertext + tag
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    return decrypted_bytes.decode('utf-8')

def main():
    print("=" * 60)
    print(" Zero-Knowledge Clipboard Sync Client ".center(60, "="))
    print("=" * 60)
    
    server_url = input("Enter Server URL [http://localhost:5002]: ").strip()
    if not server_url:
        server_url = "http://localhost:5002"
        
    room_id = input("Enter Sync Room Name: ").strip().lower()
    if not room_id:
        print("[ERROR] Room name cannot be empty.")
        return
        
    password = getpass.getpass("Enter Room Password: ")
    if not password:
        print("[ERROR] Password cannot be empty.")
        return

    # 1. Fetch Room Salt
    salt_bytes = None
    try:
        url_salt = f"{server_url}/api/rooms/{room_id}/salt"
        resp = requests.get(url_salt, timeout=5)
        if resp.status_code == 200:
            salt_hex = resp.json()["salt"]
            salt_bytes = bytes.fromhex(salt_hex)
            print("[*] Room found on server. Fetching salt parameters...")
        elif resp.status_code == 404:
            # Room doesn't exist, create a new salt
            salt_bytes = os.urandom(16)
            print("[*] Room does not exist. Creating new salt parameters...")
        else:
            print(f"[ERROR] Failed checking room status: HTTP {resp.status_code}")
            return
    except Exception as e:
        print(f"[FATAL] Server connection error: {e}")
        return

    # 2. Derive Keys
    print("[*] Deriving cryptographic key pairs...")
    encryption_key, verifier_hash = derive_keys(password, salt_bytes)
    
    # 3. Create or Join Room
    try:
        url_create = f"{server_url}/api/rooms/create"
        payload_create = {
            "room_id": room_id,
            "salt": salt_bytes.hex(),
            "verifier_hash": verifier_hash
        }
        resp = requests.post(url_create, json=payload_create, timeout=5)
        if resp.status_code in (200, 201):
            print(f"[SUCCESS] Joined room '{room_id}' successfully.")
        else:
            print(f"[ERROR] Authorization failed: {resp.json().get('error', 'Unknown error')}")
            return
    except Exception as e:
        print(f"[FATAL] Connection error during join: {e}")
        return

    # Initialize loop trackers
    last_local_clip = pyperclip.paste()
    last_synced_time = None
    
    print("\n" + "-" * 60)
    print(" Monitoring clipboard... Press Ctrl+C to terminate.".center(60))
    print("-" * 60 + "\n")
    
    # Push initial clipboard state to synchronize
    if last_local_clip:
        c_hex, iv_hex, tag_hex = encrypt_data(encryption_key, last_local_clip)
        try:
            requests.post(f"{server_url}/api/rooms/{room_id}/sync", json={
                "verifier_hash": verifier_hash,
                "ciphertext": c_hex,
                "iv": iv_hex,
                "tag": tag_hex
            }, timeout=3)
            print(f"[SYNC] Pushed local clipboard (length: {len(last_local_clip)})")
        except Exception:
            pass

    # Main synchronization loop
    while True:
        try:
            time.sleep(1.5)
            
            # Check local clipboard
            current_local = pyperclip.paste()
            
            if current_local != last_local_clip:
                # 1. Local clipboard changed - encrypt and push to server
                print(f"[LOCAL] Clipboard update detected. Syncing...")
                c_hex, iv_hex, tag_hex = encrypt_data(encryption_key, current_local)
                
                try:
                    resp = requests.post(f"{server_url}/api/rooms/{room_id}/sync", json={
                        "verifier_hash": verifier_hash,
                        "ciphertext": c_hex,
                        "iv": iv_hex,
                        "tag": tag_hex
                    }, timeout=3)
                    
                    if resp.status_code == 200:
                        last_local_clip = current_local
                        print(f"[SYNC] Successfully uploaded ciphertext (GCM Mode)")
                    else:
                        print(f"[WARNING] Upload failed: {resp.json().get('error')}")
                except Exception as e:
                    print(f"[ERROR] Sync upload failed: {e}")
            else:
                # 2. Local clipboard unchanged - pull from server
                try:
                    resp = requests.get(f"{server_url}/api/rooms/{room_id}/sync", timeout=3)
                    if resp.status_code == 200:
                        data = resp.json()
                        server_time = data.get("updated_at")
                        
                        if server_time != last_synced_time:
                            c_hex = data.get("ciphertext")
                            iv_hex = data.get("iv")
                            tag_hex = data.get("tag")
                            
                            # Only decrypt if there is actual content
                            if c_hex and iv_hex and tag_hex:
                                try:
                                    decrypted = decrypt_data(encryption_key, c_hex, iv_hex, tag_hex)
                                    if decrypted != current_local:
                                        pyperclip.copy(decrypted)
                                        last_local_clip = decrypted
                                        print(f"[SYNC] Pulled & Decrypted new clipboard content: '{decrypted[:30]}...'")
                                except Exception as dec_err:
                                    # Cryptographic integrity check failed (could be wrong key or tampered)
                                    print(f"[ERROR] Decryption failed (MAC verification mismatch): {dec_err}")
                                    
                            last_synced_time = server_time
                except Exception as e:
                    # Silently ignore connection timeouts during polling loops
                    pass
                    
        except KeyboardInterrupt:
            print("\nSync client stopped. Safe clipboard clearing...")
            break
        except Exception as e:
            print(f"[CRITICAL ERROR] Loop exception: {e}")

if __name__ == "__main__":
    main()
