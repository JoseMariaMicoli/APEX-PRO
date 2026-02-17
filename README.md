## License Update Notice

Starting from version 2.0.1 this project will transition to BSL.

Reason:
To allow sustainable development, support, and long-term maintenance while keeping the project open and transparent.

Previous versions remain under the original license.

```markdown
 █████╗ ██████╗ ███████╗██╗  ██╗     ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝      ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝       ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗       ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗      ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

        ⚡ APEX PRO v2.0: ADVERSARY EMULATION FRAMEWORK
     [ TACTICAL C2 CONSOLE & PURPLE TEAM UTILITIES ]
```
**Apex Pro v2.0** is a high-fidelity adversary emulation tool designed to replicate the behaviors of modern ransomware families (e.g., LockBit, Conti, WannaCry). It provides a safe, controlled environment to validate detection pipelines, EDR efficacy, and Incident Response (IR) readiness. Also is an industrial-strength ransomware emulation framework. It bridges the gap between simple script execution and full-scale simulation, providing a central Command & Control (C2) hub to manage the entire lifecycle of an attack—from binary compilation to real-time exfiltration tracking and finalized forensic reporting.

---

### ⚠️ DISCLAIMER

**For Educational and Authorized Security Testing Purposes Only.**

The use of this framework for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The authors assume no liability and are not responsible for any data loss, system damage, legal consequences, or misuse caused by this program. By using this software, you agree to operate within the legal boundaries of your jurisdiction.

---

## 🚀 The Evolution: v1.0 vs v2.0

| Feature | Version 1.0 (Standalone) | Version 2.0 (Integrated Console) |
| --- | --- | --- |
| **Agent Build** | Manual Base64 & `csc.exe` | **Interactive `compile` & `gen_dec` commands** |
| **Payload Delivery** | External `script.txt` resources | **Direct In-Memory string injection** |
| **Telemetry** | Raw console logs | **Real-time Database-driven Tactical Monitor** |
| **Reporting** | Basic summary | **4-Phase Forensic PDF (Persistence to Lateral)** |
| **SSL Stability** | Potential handshake crashes | **Hardened Transport Layer (Silent Timeout Fix)** |

---

## 🚀 Project Status: v2.0 Stable

* [x] AES-256-CBC Per-File Encryption
* [x] Asynchronous Python C2 Backend (Quart/aiosqlite)
* [x] Automated Metadata Exfiltration (TLS 1.2+)
* [x] Data Theft Module (T1041): Automated discovery and exfiltration
* [x] Persistence & Lateral Propagation Modules
* [x] Canary Tripwire Real-time Alerts
* [x] Basic Reporting: Forensic PDF report
* [x] Basic EDR/AV Evasion
* [x] Advanced Reporting: Forensic and IR PDF mapped to MITRE ATT&CK
* [ ] Advanced EDR/AV Evasion (In Progress)

---

## 🛠️ The Technology Behind the Engine

### 🛰️ 1. The Apex Tactical Console (`apex_console.py`)

The C2 Console is a multi-threaded Python environment managing an HTTPS server, an event monitor, and an interactive shell concurrently.

* **Integrated Build Engine:** Utilizes the Mono C# Compiler (`mcs`) to dynamically patch the `ApexRunner.cs` template. It automatically performs Base64 encoding of the core logic and injects it into a standard C# string before compilation.
* **Tactical Event Monitor:** A background thread that polls the `apex_vault.db`. It uses context-aware logic to distinguish between **ENCRYPTION** (Red alerts) and **DECRYPTION/RESTORE** (Green alerts).
* **Async Hypercorn/Quart Backend:** Hardened against "abrupt disconnects." Even if an agent exits instantly after a task, the console remains stable and suppresses SSL/Transport tracebacks.

### 💻 2. The Apex Agent (C# Wrapper + PS1 Logic)

The agent is a dual-stage binary designed to bypass common execution policies and static analysis by utilizing **unmanaged PowerShell execution**.



* **PowerShell Automation Engine:** The C# wrapper loads the PS1 logic directly into memory without spawning a `powershell.exe` process, making it significantly harder for EDR to detect via process-tree analysis.
* **Cryptography Engine (AES-256-CBC):** Emulates modern ransomware (e.g., LockBit) by using 32-byte keys and 16-byte IVs. It implements per-file encryption logic to simulate high-impact data loss.
* **Data Theft Module (T1041):** Automatically discovers and exfiltrates `.xlsx`, `.pdf`, and `.docx` via Base64-encoded streams over TLS 1.2+.
* **Persistence & Survivability (T1547.001):** Strategic registry run-key modification (`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`) ensuring the simulation persists across reboots.
* **Impact & Defacement (T1491):** Wallpaper hijacking and automated ransom note drops for psychological impact simulation.

### 📄 3. Advanced Forensic Reporting

The engine generates a professional 4-Phase mission report mapped to the MITRE ATT&CK framework:

* **PHASE I: PERSISTENCE:** Registry and startup modifications.
* **PHASE II: EXFILTRATION:** Summary of stolen metadata and documents.
* **PHASE III: ENCRYPTION:** Detailed impact analysis of the locked file system.
* **PHASE IV: LATERAL MOVEMENT:** Network discovery attempts and Canary tripwire triggers.

---

## ⚙️ Operational Workflow

### Step 1: Server Initialization

```bash
# Install tactical dependencies
pip install -r requirements.txt

# Generate SSL certificates for the secure telemetry tunnel
openssl req -x509 -newkey rsa:4096 -keyout apex_key.pem -out apex_cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

# Start the Apex v2.0 Console
python3 apex_console.py

```

### Step 2: Lab Preparation & Automated Build

**[B] Lab Preparation: Generate dummy data**
On the Windows victim machine, prepare the target environment:

```powershell
# Usage: .\GenerateVictimData.ps1 -RootPath <Path>
powershell.exe -ExecutionPolicy Bypass -File .\GenerateVictimData.ps1 -RootPath "C:\SimulationData"

```

**[C] Building Agents**
Generate your simulation binaries directly from the Apex shell.
*Prerequisite: Ensure System.Management.Automation.dll is in the project root.*

```apex
Apex » compile x86      # Generate the primary Encryption Agent
Apex » gen_dec x86      # Generate the standalone Simulation Decryptor

```

### Step 3: Deployment & Live Monitoring

Deploy the binary to your target VM. As the agent moves through the phases, the C2 Console provides live feedback:

* `[ALERT] New ENCRYPTION activity from 192.168.56.10` (Bold Red)
* `[ALERT] New DECRYPTION activity from 192.168.56.10` (Bold Green)

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

---

## 🔒 Rules of Engagement & Safety

1. **Host-Only Networking:** Simulations **MUST** occur in isolated virtual environments.
2. **Authorized Use Only:** This framework is for purple-teaming and authorized IR training.
3. **Decryption:** The `ApexDecryptor` removes all persistence and restores files. A user logout is recommended to refresh the defaced wallpaper.

---

**Apex Pro v2.0 - The Apex of Adversary Emulation.**