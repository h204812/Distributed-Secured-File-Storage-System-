
import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os
import struct
import json
import base64
import hmac
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time




#----------------------------------------------------- CONSTANTS -----------------------------------------#
CHUNK_SIZE = 1024  # Size of each file chunk in bytes
SERVER_NODES = ["http://127.0.0.1:5000", "http://127.0.0.1:5001", "http://127.0.0.1:5002"]
METADATA_SERVER_URL = "http://127.0.0.1:5003"



CLIENT_PRIVATE_KEY_FILE = "clientA_private.pem"
CLIENT_PUBLIC_KEY_FILE = "clientA_public.pem"
METADATA_SERVER_PUBLIC_KEY_FILE = "metadata_server_public.pem"

#-----------------------------------------------------------------------------------------------------------#



#---------------------------------------------- RSA KEY GENERATION -----------------------------------------#

def generate_rsa_key():
    """Generates an RSA key pair and stores it locally."""
    if not os.path.exists(CLIENT_PRIVATE_KEY_FILE) or not os.path.exists(CLIENT_PUBLIC_KEY_FILE):
        key = RSA.generate(2048)
        private_key = key.export_key(format="DER")
        public_key = key.publickey().export_key()

        # Save keys locally
        with open(CLIENT_PRIVATE_KEY_FILE+".bin", "wb") as f:
            f.write(private_key)
        with open(CLIENT_PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key)

        print(" RSA Key Pair Generated.")
        send_public_key_to_metadata_server(public_key)
    else:
        print(" RSA Keys Already Exist. Skipping Generation.")

#-------------------------------------------------------------------------------------------------------------#



#-------------------------------------------- LOADING PRIVATE KEY ----------------------------------------------#
def load_private_key():
    """Loads the client's private RSA key."""
    if not os.path.exists(CLIENT_PRIVATE_KEY_FILE + ".bin"):
        print(" Private Key Not Found. Generate it first.")
        return None
    with open(CLIENT_PRIVATE_KEY_FILE+".bin", "rb") as f:
        return RSA.import_key(f.read())
#----------------------------------------------------------------------------------------------------------------#



#------------------------------------------- EXCHANGE OF KEYS -----------------------------------------------------#



def send_public_key_to_metadata_server(public_key):
    """Sends the clients public key to the metadata server."""
    response = requests.post(f"{METADATA_SERVER_URL}/store_client_key", json={
        "client_name": "clientA",  
        "public_key": base64.b64encode(public_key).decode()
    })

    if response.status_code == 200:
        print(" Client Public Key Successfully Sent to Metadata Server.")
    else:
        print(" Failed to Store Public Key:", response.text)


def get_metadata_server_public_key():
    """Retrieves and stores the metadata server's public key."""
    if os.path.exists(METADATA_SERVER_PUBLIC_KEY_FILE):
        print(" Metadata Server Public Key Already Stored.")
        return

    response = requests.get(f"{METADATA_SERVER_URL}/get_metadata_server_key")
    if response.status_code == 200:
        metadata_server_key = base64.b64decode(response.json()["public_key"])
        print(metadata_server_key)

        # Save the metadata server's public key locally
        with open(METADATA_SERVER_PUBLIC_KEY_FILE, "wb") as f:
            f.write(metadata_server_key)

        print("Metadata Server Public Key Retrieved & Stored.")
    else:
        print(" Failed to Retrieve Metadata Server Public Key.")

#---------------------------------------------------------------------------------------------------------#


#---------------------------- encryption and decryption Functions---------------------------------------#

def encrypt_file(file_path, aes_key):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return ciphertext, nonce, tag

def compute_hmac(data,hmac_key):
    """Computes HMAC for a given data chunk using the stored secret key."""
   ## hmac_key = load_hmac_key()
    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()

# Encrypt a message using RSA public key
def rsa_encrypt(data, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return base64.b64encode(cipher_rsa.encrypt(data)).decode()

# Decrypt a message using RSA private key
def rsa_decrypt(encrypted_data, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(base64.b64decode(encrypted_data))

# ---------------------------------------------------------------------------------------------------------#

#--------------------------Simple splitting and joining functions------------------------------------#

def simple_split(data, chunk_size):
    """Split data into chunks of size chunk_size (last chunk may be shorter)."""
    parts = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    return parts

def simple_join(parts):
    """Reassemble data by concatenating parts."""
    return b"".join(parts)
#----------------------------------------------------------------------------------------------------------#


#--------------------------------- UPLOADING PART ---------------------------------------------------------#

def upload_keys(file_name,aes_key,hmac_key):
   
    
    with open(METADATA_SERVER_PUBLIC_KEY_FILE, "rb") as f:
        metadata_server_public_key = f.read()
    
    encrypted_aes_key = rsa_encrypt(aes_key, metadata_server_public_key)
    encrypted_hmac_key = rsa_encrypt(hmac_key, metadata_server_public_key)

   # print("ecnrypted keys are: ")
   # print(encrypted_aes_key,"\n hmac key: \n",encrypted_hmac_key)
   # print(file_name)

    response = requests.post(f"{METADATA_SERVER_URL}/store_keys", json={
        "file_name": file_name,
        "encrypted_aes_key": encrypted_aes_key,
        "encrypted_hmac_key": encrypted_hmac_key
    })

    if response.status_code == 200:
        print(" Keys uploaded securely.")
    else:
        print(" Error uploading keys:", response.text)


def upload_file(file_path):
    file_name = os.path.basename(file_path)
     

    aes_key = get_random_bytes(32)
    hmac_key = get_random_bytes(32)

    upload_keys(file_name,aes_key,hmac_key) 
    


    ciphertext, nonce, tag = encrypt_file(file_path, aes_key)
    
    parts = [ciphertext[i:i + CHUNK_SIZE] for i in range(0, len(ciphertext), CHUNK_SIZE)]
    chunk_locations = {}

    chunk_locations = {}

    for i, part in enumerate(parts):
        server_url = SERVER_NODES[i % len(SERVER_NODES)]
        chunk_id = f"{os.path.basename(file_path)}_part{i}"
        
        # Compute HMAC for the chunk

        chunk_hmac = compute_hmac(part,hmac_key)

        response = requests.post(f"{server_url}/store_chunk", json={
            "chunk_id": chunk_id,
            "chunk_data": part.hex(),
            "hmac": chunk_hmac  # Send HMAC along with the chunk
        })

        if response.status_code == 200:
            chunk_locations[chunk_id] = server_url
        else:
            print(f"Error storing chunk {chunk_id} on {server_url}: {response.text}")

    metadata = {
        "file_name": os.path.basename(file_path),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "chunk_locations": chunk_locations,
        "num_parts": len(parts)
    }

    response = requests.post(f"{METADATA_SERVER_URL}/store_metadata", json={
        "file_name": os.path.basename(file_path),
        "metadata": metadata
    })

    if response.status_code == 200:
        print(" File uploaded successfully with integrity verification.")
    else:
        print(" Error storing metadata.")

    del aes_key
    del hmac_key

#---------------------------------------------------------------------------------------------------------#



#------------------------------------- DIGITAL SIGNATURE  ------------------------------------------------#
def sign_request(message):
    """Signs the request using RSA for authentication."""
    key = load_private_key()
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)

    return  base64.b64encode(signature).decode()  # Return  signature
#-----------------------------------------------------------------------------------------------------------#



#--------------------------------------- DOWNLOADING -------------------------------------------------------#
def retrieve_keys(file_name):
    """Requests encrypted keys from the metadata server with authentication."""
    client_name = "clientA"  
    
    timestamp = str(int(time.time()))

    message = f"{client_name}:{file_name}:{timestamp}"
    signature = sign_request(message)

    response = requests.get(
        f"{METADATA_SERVER_URL}/get_keys/{file_name}",
        params={"client_name": client_name, "message": message, 
                },headers={"D-Signature":signature}
    )
    
   # print(f" Server Response: {response.status_code} - {response.text}")  # Debugging

    if response.status_code != 200:
        print(f" Failed to retrieve keys.")
        return None, None

    encrypted_keys = response.json()

    with open(CLIENT_PRIVATE_KEY_FILE+".bin", "rb") as f:
        private_key = f.read()

    aes_key = rsa_decrypt(encrypted_keys["encrypted_aes_key"], private_key)
    hmac_key = rsa_decrypt(encrypted_keys["encrypted_hmac_key"], private_key)

    return aes_key, hmac_key




def download_file(file_name):
    """Downloads a file and verifies integrity using HMAC."""
    aes_key, hmac_key = retrieve_keys(file_name)
    if not aes_key or not hmac_key:
        print(" Unable to retrieve keys. Download aborted.")
        return

    response = requests.get(f"{METADATA_SERVER_URL}/get_metadata/{file_name}")
    if response.status_code != 200:
        print(" File not found on metadata server.")
        return
    
    metadata = response.json()["metadata"]
   # print(" Retrieved metadata:", metadata)

    num_parts = metadata["num_parts"]
    parts = [None] * num_parts

    for chunk_id, server_url in metadata["chunk_locations"].items():
        try:
            response = requests.get(f"{server_url}/get_chunk/{chunk_id}")
            if response.status_code == 200:
                chunk_data = bytes.fromhex(response.json()["chunk_data"])
                stored_hmac = response.json()["hmac"]

                # Compute HMAC on retrieved chunk
                computed_hmac = compute_hmac(chunk_data,hmac_key)

                # Verify Integrity
                if computed_hmac != stored_hmac:
                    print(f" Integrity check failed for chunk {chunk_id}. FILE INTEGRITY LOST!")
                    return
                
                index = int(chunk_id.split("_part")[-1])
                parts[index] = chunk_data
            else:
                print(f" Failed to retrieve chunk {chunk_id} from {server_url}.")
        except Exception as e:
            print(f" Error retrieving chunk {chunk_id}: {e}")

    if any(part is None for part in parts):
        print(" Not all parts were retrieved. File cannot be reassembled.")
        return

    ciphertext = simple_join(parts)


    nonce = bytes.fromhex(metadata["nonce"])
    tag = bytes.fromhex(metadata["tag"])
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(f"downloaded_{file_name}", "wb") as f:
        f.write(plaintext)
    print(f" File downloaded and saved as downloaded_{file_name}.")

#--------------------------------------------------------------------------------------------------------#


def initilizeClient():
    generate_rsa_key()
    get_metadata_server_public_key()

# --------------------------------------- MAIN FUNCTION ---------------------------------------------------#

def main():
    initilizeClient()
    
    while True:
        print("\n1. Upload File")
        print("2. Download File")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            file_path = input("Enter the file path: ")
            upload_file(file_path)
        elif choice == "2":
            file_name = input("Enter the file name: ")
            download_file(file_name)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()


#----------------------------------------------------------- THE END -----------------------------------------#
