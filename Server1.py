
from flask import Flask, request, jsonify
import os
import hmac
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)

#-------------------------------------- STORAGE --------------------------------#

# Node storage (Chunk Data + HMACs)
chunk_storage = {}  # Stores {chunk_id: (chunk_data, hmac_value)}
share_storage = {}

#-------------------------------------------------------------------------------#





#---------------------------------------- API'S FOR STORING THE DATA --------------------#


@app.route("/store_chunk", methods=["POST"])
def store_chunk():
    chunk_id = request.json["chunk_id"]
    chunk_data = request.json["chunk_data"]
    received_hmac = request.json["hmac"]


    # Store chunk with its HMAC
    chunk_storage[chunk_id] = (chunk_data, received_hmac)
    return jsonify({"status": "success"})


@app.route("/get_chunk/<chunk_id>", methods=["GET"])
def get_chunk(chunk_id):
    chunk_entry = chunk_storage.get(chunk_id)
    if chunk_entry:
        chunk_data, stored_hmac = chunk_entry
        return jsonify({"status": "success", "chunk_data": chunk_data, "hmac": stored_hmac})
    else:
        return jsonify({"status": "error", "message": "Chunk not found"}), 404
#-------------------------------------------------------------------------------------------#


#--------------------------------- MAIN FUNCTION -------------------------------------------#

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

#-------------------------------------------------------------------------------------------#