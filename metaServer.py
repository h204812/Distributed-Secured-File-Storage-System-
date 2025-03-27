from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import base64
import time
from Crypto.Hash import HMAC, SHA256
import requests
import threading



app = Flask(__name__)


#------------------------------------------ STORAGE -----------------------------------------------#

# In-memory dictionary to store encrypted metadata
metadata_store = {}
encrypted_keys_store = {}
client_keys_store = {} 
#---------------------------------------------------------------------------------------------------#


#-------------------------------------------CONSTANTS-----------------------------------------------#
METADATA_PRIVATE_KEY_FILE = "metadata_private.pem"
METADATA_PUBLIC_KEY_FILE = "metadata_public.pem"
#----------------------------------------------------------------------------------------------------#

#------------------------------------ RSA KEY GENERATION ------------------------------------------------#
def generate_metadata_server_keys():
    """Generates RSA key pair for the metadata server if not already generated."""
    if not os.path.exists(METADATA_PRIVATE_KEY_FILE) or not os.path.exists(METADATA_PUBLIC_KEY_FILE):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(METADATA_PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key)
        with open(METADATA_PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key)

        print(" Metadata Server RSA Keys Generated.")
    else:
        print(" Metadata Server RSA Keys Already Exist.")
#--------------------------------------------------------------------------------------------------------#



#---------------------------------------- ENCRYPTION AND DECRYPTION -------------------------------------#

def encrypt_with_client_public_key(data, client_name):
    """Encrypts data using a client’s stored public key."""
    if client_name not in client_keys_store:
        return None

    public_key = RSA.import_key(base64.b64decode(client_keys_store[client_name]))
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)

    return base64.b64encode(encrypted_data).decode()

def decrypt_with_metadata_private_key(encrypted_data):
    """Decrypts data using the Metadata Server’s Private Key."""
    with open(METADATA_PRIVATE_KEY_FILE, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))

    return decrypted_data

def decrypt_with_metadata_private_key(encrypted_data):
    """Decrypts data using the Metadata Server’s Private Key."""
    with open(METADATA_PRIVATE_KEY_FILE, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_data))

def encrypt_with_metadata_public_key(data):
    """Encrypts data using Metadata Server’s Public Key."""
    with open(METADATA_PUBLIC_KEY_FILE, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(data)).decode()

def aes_decrypt(ciphertext, key, nonce, tag):
    """Decrypts AES-encrypted data."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def aes_encrypt(plaintext, key):
    """Encrypts data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, cipher.nonce, tag

#------------------------------------------------------------------------------------------------------#



#---------------------------- API'S FOR  CLIENT'S PUBLIC KEY -------------------------------------------#
    
@app.route('/store_client_key', methods=['POST'])
def store_client_key():
    """Stores a client’s public key at a separate route."""
    data = request.json
    client_name = data.get("client_name")
    public_key_b64 = data.get("public_key")

    if not client_name or not public_key_b64:
        return jsonify({"error": "Invalid request"}), 400
    print("client_name is : ",client_name)
    client_keys_store[client_name] = public_key_b64
    print(client_keys_store)   # Store as base64 string
    return jsonify({"message": f"Public key for {client_name} stored successfully"}), 200


@app.route('/get_client_key/<client_name>', methods=['GET'])
def get_client_key(client_name):
    """Retrieves a stored client’s public key."""
    print(client_keys_store)
    if client_name not in client_keys_store:
        return jsonify({"error": "Client key not found"}), 404

    return jsonify({"public_key": client_keys_store[client_name]}), 200

#----------------------------------------------------------------------------------------------------#

#------------------------------------------- API'S FOR METADATA PUBLIC KEY --------------------------#

@app.route('/get_metadata_server_key', methods=['GET'])
def get_metadata_server_key():
    """Returns the metadata server’s public key to clients."""
    if not os.path.exists(METADATA_PUBLIC_KEY_FILE):
        return jsonify({"error": "Metadata server public key not found"}), 500

    with open(METADATA_PUBLIC_KEY_FILE, "rb") as f:
        public_key = f.read()

    return jsonify({"public_key": base64.b64encode(public_key).decode()}), 200
#-----------------------------------------------------------------------------------------------------#

#--------------------------------------- API'S FOR AES AND SECRET KEYS -------------------------------#

@app.route('/store_keys', methods=['POST'])
def store_metadata_keys():
    """Stores encrypted AES & HMAC keys for a file."""
    data = request.json
    file_name = data.get("file_name")
    encrypted_aes_key = data.get("encrypted_aes_key")
    encrypted_hmac_key = data.get("encrypted_hmac_key")

    # print("ecnrypted keys are: ")
    # print(encrypted_aes_key,"\n hmac key: \n",encrypted_hmac_key)
    # print(file_name)

    if not file_name or not encrypted_aes_key or not encrypted_hmac_key:
        return jsonify({"error": "Invalid request"}), 400

    encrypted_keys_store[file_name] = {
        "encrypted_aes_key": encrypted_aes_key,
        "encrypted_hmac_key": encrypted_hmac_key
    }
    return jsonify({"message": "Encrypted keys stored successfully"}), 200

@app.route('/get_keys/<file_name>', methods=['GET'])
def get_metadata_keys(file_name):
    """Decrypts AES & HMAC keys and re-encrypts them for the requesting client."""
    client_name = request.args.get("client_name")
    signature = request.headers.get("D-Signature")
    message = request.args.get("message")

    if not client_name or not message or not signature:
        return jsonify({"error": "Missing authentication parameters"}), 400
    
    if not verify_signature(client_name, message, signature):
        return jsonify({"error": "Signature verification failed"}), 403
    
    if not client_name :
        return jsonify({"error": "Client name is required"}), 400
    
    print("while giving key : ")
    print(client_name)
    print(client_keys_store)
    
    if client_name not in client_keys_store:
        return jsonify({"error": "Client public key not found"}), 404
    
    print("file name and there keys are: ")
    print(encrypted_keys_store)
    print(file_name)
    if file_name not in encrypted_keys_store:
        return jsonify({"error": "File keys not found"}), 404

    encrypted_keys = encrypted_keys_store[file_name]

    # Decrypt AES & HMAC Keys with Metadata Server's Private Key
    decrypted_aes = decrypt_with_metadata_private_key(encrypted_keys["encrypted_aes_key"])
    decrypted_hmac = decrypt_with_metadata_private_key(encrypted_keys["encrypted_hmac_key"])

    # Encrypt with Client's Public Key
    encrypted_aes_for_client = encrypt_with_client_public_key(decrypted_aes, client_name)
    encrypted_hmac_for_client = encrypt_with_client_public_key(decrypted_hmac, client_name)

    if not encrypted_aes_for_client or not encrypted_hmac_for_client:
        return jsonify({"error": "Encryption failed"}), 500
    

    return jsonify({
        "encrypted_aes_key": encrypted_aes_for_client,
        "encrypted_hmac_key": encrypted_hmac_for_client
    }), 200
#----------------------------------------------------------------------------------------------------#


#--------------------------------- VERIFICATION OF SIGNATURE ----------------------------------------#
def verify_signature(client_name, message, signature_b64):
    """Verifies the signature using the client's stored public key."""
    if client_name not in client_keys_store:
        print(f" Client {client_name} public key not found.")
        return False

    try:
        # Load client's public key
        client_public_key = RSA.import_key(base64.b64decode(client_keys_store[client_name]))

        # Decode signature from base64
        signature = base64.b64decode(signature_b64)

        # Compute hash of the message
        h = SHA256.new(message.encode())

        # Verify the signature
        pkcs1_15.new(client_public_key).verify(h, signature)
        print(" Signature verified successfully.")
        return True
    except (ValueError, TypeError):
        print(" Signature verification failed.")
        return False
#------------------------------------------------------------------------------------------------------#

#------------------------------------ API'S FOR CHUNK LOCATIONS ---------------------------------------#
@app.route('/store_metadata', methods=['POST'])
def store_metadata():
    data = request.json
    file_name = data.get("file_name")
    metadata = data.get("metadata")

    if not file_name or not metadata:
        return jsonify({"error": "Invalid request"}), 400

    metadata_store[file_name] = metadata
    return jsonify({"message": "Metadata stored successfully"}), 200

@app.route('/get_metadata/<file_name>', methods=['GET'])
def get_metadata(file_name):
    if file_name not in metadata_store:
        return jsonify({"error": "Metadata not found"}), 404

    return jsonify({"metadata": metadata_store[file_name]}), 200
#-------------------------------------------------------------------------------------------------------#





#--------------------------------------- MAIN FUNCTION ------------------------------------------------#

if __name__ == '__main__':
    generate_metadata_server_keys()
    app.run(port=5003, debug=True)


#-------------------------------------------- THE END -----------------------------------------------------#