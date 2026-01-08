import sqlite3
import json

DB_FILE = "apex_vault.db"

def generate_report():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, time, payload, canary_tripped FROM telemetry")
        rows = cursor.fetchall()
        
        print(f"\n{'='*60}\nAPEX PRO SIMULATION REPORT\n{'='*60}")
        for row in rows:
            status = "!!! CANARY TRIPPED !!!" if row[3] else "Standard Exfil"
            print(f"\n[Victim IP]: {row[0]} | [Time]: {row[1]}")
            print(f"[Status]: {status}")
            print(f"[Files Impacted]:\n{row[2]}")
            print("-" * 40)
        conn.close()
    except Exception as e:
        print(f"Error reading database: {e}")

if __name__ == "__main__":
    generate_report()