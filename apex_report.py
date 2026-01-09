import sqlite3
import json
from fpdf import FPDF

DB_FILE = "apex_vault.db"

class ApexPDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_text_color(200, 0, 0)
        self.cell(0, 10, "APEX PRO: ADVERSARY EMULATION REPORT", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def generate_report():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, time, payload, canary_tripped FROM telemetry")
        rows = cursor.fetchall()
        
        # 1. Terminal Output
        print(f"\n{'='*60}\nAPEX PRO SIMULATION REPORT\n{'='*60}")
        
        # 2. PDF Setup
        pdf = ApexPDF()
        pdf.add_page()
        
        for row in rows:
            ip, time, payload, canary = row
            status = "!!! CANARY TRIPPED !!!" if canary else "Standard Exfil"
            
            # Print to Terminal
            print(f"\n[Victim IP]: {ip} | [Time]: {time}")
            print(f"[Status]: {status}")
            print("-" * 40)

            # Add to PDF
            pdf.set_font("Arial", "B", 12)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 10, f"Victim IP: {ip} | Timestamp: {time}", ln=True, fill=True)
            
            pdf.set_font("Arial", "", 10)
            if canary:
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, f"ALERT STATUS: {status}", ln=True)
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.cell(0, 8, f"Status: {status}", ln=True)

            pdf.multi_cell(0, 5, f"Exfiltrated Files:\n{payload}")
            pdf.ln(5)

        pdf.output("Apex_Simulation_Report.pdf")
        print(f"\n[+] PDF Report generated: Apex_Simulation_Report.pdf")
        conn.close()

    except Exception as e:
        print(f"Error reading database: {e}")

if __name__ == "__main__":
    generate_report()