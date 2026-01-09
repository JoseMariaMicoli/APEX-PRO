import sqlite3
import json
import os
from fpdf import FPDF

DB_FILE = "apex_vault.db"

class ApexHybridPDF(FPDF):
    def header(self):
        # The professional header you liked
        self.set_fill_color(33, 37, 41) 
        self.rect(0, 0, 210, 25, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", "B", 15)
        self.cell(0, 5, "APEX PRO | ADVERSARY EMULATION FORENSICS", ln=True, align="C")
        self.set_font("Arial", "", 8)
        self.cell(0, 5, "CONFIDENTIAL - INTERNAL SIMULATION USE ONLY", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Apex Simulation Report | Page {self.page_no()}", align="C")

def generate_report():
    if not os.path.exists(DB_FILE):
        print(f"[!] Error: {DB_FILE} not found.")
        return

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, time, payload, canary_tripped FROM telemetry ORDER BY time DESC")
        rows = cursor.fetchall()
        
        pdf = ApexHybridPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        
        for ip, time, payload, canary in rows:
            # --- Professional Metadata Section ---
            pdf.set_font("Arial", "B", 10)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 8, f" DESTINATION: {ip} ", ln=True, fill=True)
            pdf.set_font("Arial", "", 9)
            pdf.cell(0, 6, f" TIMESTAMP:   {time}", ln=True, fill=True)
            
            if canary:
                pdf.set_text_color(200, 0, 0)
                pdf.cell(0, 6, " STATUS:      [!] CRITICAL - SENSITIVE EXFILTRATION", ln=True, fill=True)
            else:
                pdf.set_text_color(0, 120, 0)
                pdf.cell(0, 6, " STATUS:      [*] INFO - SYSTEM DISCOVERY LOG", ln=True, fill=True)
            
            pdf.ln(4)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Courier", "B", 9)
            pdf.cell(0, 5, "EXFILTRATED_DATA_STREAM:", ln=True)
            pdf.ln(2)

            # --- THE JSON FORMATTER ---
            pdf.set_font("Courier", "", 9)
            try:
                # 1. First Pass: Load the main payload
                data = json.loads(payload)
                
                # 2. Check for the 'log' wrapper (PowerShell sends file lists this way)
                if isinstance(data, dict) and "log" in data:
                    log_content = data["log"]
                    # If 'log' is a string, it's double-encoded JSON. Load it again.
                    if isinstance(log_content, str):
                        data = json.loads(log_content)
                    else:
                        data = log_content

                # 3. Print as clean, expanded blocks
                if isinstance(data, list):
                    pdf.cell(0, 5, "[", ln=True)
                    for i, item in enumerate(data):
                        # Constructing the exact block style you wanted
                        name = item.get('Name', 'Unknown')
                        size = item.get('Length', 0)
                        
                        pdf.cell(0, 5, "  {", ln=True)
                        pdf.cell(0, 5, f'    "Name": "{name}",', ln=True)
                        pdf.cell(0, 5, f'    "Length": {size}', ln=True)
                        
                        # Add closing brace and comma if needed
                        closing = "  }," if i < len(data) - 1 else "  }"
                        pdf.cell(0, 5, closing, ln=True)
                    pdf.cell(0, 5, "]", ln=True)
                else:
                    # Single object formatting
                    pdf.multi_cell(0, 5, json.dumps(data, indent=4))

            except Exception:
                # Fallback for plain text (LOOT)
                pdf.multi_cell(0, 5, str(payload).replace('LOOT|', 'EXTRACTED_FILE: '))

            pdf.ln(15) # Clear gap between different hosts

        output_name = "Apex_Final_Report.pdf"
        pdf.output(output_name)
        print(f"[+] Success! Check {output_name}")
        conn.close()

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    generate_report()