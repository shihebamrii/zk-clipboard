import unittest
import os
import json
from server import app, rooms
from client import derive_keys, encrypt_data, decrypt_data
from cryptography.exceptions import InvalidTag

class TestZKClipboard(unittest.TestCase):
    
    def setUp(self):
        # Clear mock rooms in memory database before each test
        rooms.clear()
        self.client = app.test_client()

    def test_key_derivation(self):
        password = "secret_password"
        salt = os.urandom(16)
        
        key1, hash1 = derive_keys(password, salt)
        key2, hash2 = derive_keys(password, salt)
        
        # Consistent key derivation
        self.assertEqual(key1, key2)
        self.assertEqual(hash1, hash2)
        
        # Secret separation: keys should not be equal to verifier hashes
        self.assertNotEqual(key1.hex(), hash1)
        
        # Changing password changes keys
        key3, hash3 = derive_keys("different_password", salt)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(hash1, hash3)

    def test_encryption_decryption(self):
        password = "clipboard_key"
        salt = os.urandom(16)
        key, _ = derive_keys(password, salt)
        
        secret_text = "This is highly confidential information."
        
        # Encrypt
        ciphertext, iv, tag = encrypt_data(key, secret_text)
        
        # Verify encryption occurred
        self.assertNotEqual(secret_text, ciphertext)
        
        # Decrypt
        decrypted = decrypt_data(key, ciphertext, iv, tag)
        self.assertEqual(secret_text, decrypted)

    def test_decryption_mismatch_fails(self):
        salt = os.urandom(16)
        key_correct, _ = derive_keys("pass1", salt)
        key_wrong, _ = derive_keys("pass2", salt)
        
        secret_text = "Highly secure text"
        
        ciphertext, iv, tag = encrypt_data(key_correct, secret_text)
        
        # Decrypting with wrong key must raise InvalidTag (integrity check fail)
        with self.assertRaises(InvalidTag):
            decrypt_data(key_wrong, ciphertext, iv, tag)

    def test_server_room_creation(self):
        payload = {
            "room_id": "lab-room",
            "salt": "abc123hex",
            "verifier_hash": "verifier123hex"
        }
        
        # Create
        response = self.client.post("/api/rooms/create", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 201)
        
        # Create same room with correct password (verifier)
        response_join = self.client.post("/api/rooms/create", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response_join.status_code, 200)
        
        # Join room with wrong verifier (simulates wrong password)
        payload_wrong = payload.copy()
        payload_wrong["verifier_hash"] = "wrongverifier"
        response_wrong = self.client.post("/api/rooms/create", data=json.dumps(payload_wrong), content_type="application/json")
        self.assertEqual(response_wrong.status_code, 401)

    def test_server_sync_authorization(self):
        # 1. Setup room
        rooms["sync-room"] = {
            "salt": "saltval",
            "verifier_hash": "correcthash",
            "ciphertext": "",
            "iv": "",
            "tag": "",
            "updated_at": "now"
        }
        
        # 2. Push clipboard update with correct hash
        payload = {
            "verifier_hash": "correcthash",
            "ciphertext": "cipherhex",
            "iv": "ivhex",
            "tag": "taghex"
        }
        
        response = self.client.post("/api/rooms/sync-room/sync", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        
        # 3. Pull updates
        response_get = self.client.get("/api/rooms/sync-room/sync")
        self.assertEqual(response_get.status_code, 200)
        get_data = json.loads(response_get.data)
        self.assertEqual(get_data["ciphertext"], "cipherhex")
        
        # 4. Push with incorrect hash (unauthorized write)
        payload_bad = payload.copy()
        payload_bad["verifier_hash"] = "incorrecthash"
        response_bad = self.client.post("/api/rooms/sync-room/sync", data=json.dumps(payload_bad), content_type="application/json")
        self.assertEqual(response_bad.status_code, 401)

if __name__ == "__main__":
    unittest.main()
