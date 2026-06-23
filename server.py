import os
from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

# Port configuration (default 5002)
PORT = int(os.environ.get("CLIP_PORT", "5002"))

# In-memory storage for clipboard rooms
# Structure:
# {
#   "room_id": {
#       "salt": "hex_salt",
#       "verifier_hash": "hex_verifier_hash",
#       "ciphertext": "",
#       "iv": "",
#       "tag": "",
#       "updated_at": "timestamp"
#   }
# }
rooms = {}

@app.route('/api/rooms/create', methods=['POST'])
def create_room():
    data = request.get_json() or {}
    room_id = data.get("room_id")
    salt = data.get("salt")
    verifier_hash = data.get("verifier_hash")
    
    if not room_id or not salt or not verifier_hash:
        return jsonify({"error": "Missing required parameters: room_id, salt, verifier_hash"}), 400
        
    room_id = room_id.lower().strip()
    
    if room_id in rooms:
        # Room exists, verify if key verifier matches (indicates correct password)
        if rooms[room_id]["verifier_hash"] == verifier_hash:
            return jsonify({"status": "exists", "message": "Joined existing room"}), 200
        else:
            return jsonify({"error": "Incorrect password for this room ID"}), 401
            
    # Create new room
    rooms[room_id] = {
        "salt": salt,
        "verifier_hash": verifier_hash,
        "ciphertext": "",
        "iv": "",
        "tag": "",
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    print(f"[*] New Sync Room Created: {room_id}")
    return jsonify({"status": "created", "message": "New secure room created"}), 201

@app.route('/api/rooms/<room_id>/salt', methods=['GET'])
def get_room_salt(room_id):
    room_id = room_id.lower().strip()
    if room_id in rooms:
        return jsonify({"salt": rooms[room_id]["salt"]})
    return jsonify({"error": "Room not found"}), 404

@app.route('/api/rooms/<room_id>/sync', methods=['GET'])
def get_clipboard(room_id):
    room_id = room_id.lower().strip()
    if room_id not in rooms:
        return jsonify({"error": "Room not found"}), 404
        
    room = rooms[room_id]
    return jsonify({
        "ciphertext": room["ciphertext"],
        "iv": room["iv"],
        "tag": room["tag"],
        "updated_at": room["updated_at"]
    })

@app.route('/api/rooms/<room_id>/sync', methods=['POST'])
def update_clipboard(room_id):
    room_id = room_id.lower().strip()
    if room_id not in rooms:
        return jsonify({"error": "Room not found"}), 404
        
    data = request.get_json() or {}
    verifier_hash = data.get("verifier_hash")
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")
    tag = data.get("tag")
    
    if not verifier_hash or ciphertext is None or iv is None or tag is None:
        return jsonify({"error": "Missing parameters"}), 400
        
    # Authenticate write permissions using the hash verifier
    if rooms[room_id]["verifier_hash"] != verifier_hash:
        return jsonify({"error": "Unauthorized: Invalid room credentials"}), 401
        
    # Update room payload
    rooms[room_id]["ciphertext"] = ciphertext
    rooms[room_id]["iv"] = iv
    rooms[room_id]["tag"] = tag
    rooms[room_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    print(f"[SYNC] Room {room_id} updated with {len(ciphertext)} bytes of ciphertext")
    return jsonify({"status": "success", "message": "Clipboard synced"})

if __name__ == '__main__':
    print(f"[*] Zero-Knowledge Clipboard Server listening on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
