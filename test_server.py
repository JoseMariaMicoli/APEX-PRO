import asyncio, base64, aiosqlite, os, logging
from quart import Quart, request, jsonify
# Ensure these are installed: pip install quart cryptography aiosqlite

app = Quart(__name__)
DB_FILE = os.path.join(os.getcwd(), "apex_vault.db")

# Force logging to be visible on Arch console
logging.basicConfig(level=logging.INFO)

@app.before_serving
async def startup():
    print(f"[!] DB PATH: {DB_FILE}")
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS telemetry 
             (id INTEGER PRIMARY KEY, ip TEXT, time DATETIME DEFAULT CURRENT_TIMESTAMP, 
              payload TEXT, canary_tripped INTEGER)''')
        await db.commit()
    print("[*] APEX C2: Ready and listening on https://0.0.0.0:443")

@app.route('/api/v1/telemetry', methods=['POST'])
async def telemetry():
    # This line triggers the MOMENT any data hits the port
    print(f"\n[>>>] ALERT: Incoming connection from {request.remote_addr}")
    
    try:
        data = await request.get_json()
        if not data:
            print("[!] Error: Received request with NO JSON body.")
            return jsonify({"error": "no data"}), 400
            
        print(f"[+] Received Payload: {data.get('payload')[:20]}...")
        
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("INSERT INTO telemetry (ip, payload, canary_tripped) VALUES (?, ?, 0)", 
                           (request.remote_addr, data.get('payload')))
            await db.commit()
            
        print("[SUCCESS] Data committed to apex_vault.db")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        print(f"[CRITICAL ERROR] {str(e)}")
        return jsonify({"status": "error"}), 500

from hypercorn.config import Config
from hypercorn.asyncio import serve

if __name__ == '__main__':
    cert_path = 'apex_cert.pem'
    key_path = 'apex_key.pem'

    config = Config()
    config.bind = ["0.0.0.0:443"]
    config.certfile = cert_path
    config.keyfile = key_path

    print(f"[*] Manually forcing HTTPS on {config.bind}")
    asyncio.run(serve(app, config))