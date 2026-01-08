# APEX-PRO
APEX-PRO: Ransomware Emulation Framework - Adversary Emulation and Purple Team Framework

```text
 █████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔══██╗██╔══██╗██╔═══██╗
███████║██████╔╝█████╗   ╚███╔╝     ██████╔╝██████╔╝██║   ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ██╔═══╝ ██╔══██╗██║   ██║
██║  ██║██║     ███████╗██╔╝ ██╗    ██║     ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

            APEX PRO: RANSOMWARE EMULATION FRAMEWORK
         [ ADVERSARY EMULATION & PURPLE TEAM FRAMEWORK ]

================================================================
1. PROJECT OVERVIEW
-------------------
Apex Pro is a high-fidelity adversary emulation tool designed to 
replicate the behaviors of modern ransomware families (e.g., LockBit, 
Conti). It provides a safe, controlled environment to validate 
detection pipelines, EDR efficacy, and Incident Response (IR) readiness.

2. FEATURES ARCHITECTURE
------------------------
* Cryptography: AES-256-CBC per-file encryption using native .NET 
  providers for high-entropy security simulation.
* Multi-Victim C2: Asynchronous Python backend utilizing Quart and 
  aiosqlite for scalable, persistent victim tracking.
* Stealth Exfiltration: Metadata manifests are AES-encrypted locally 
  before being tunneled through HTTPS (TLS 1.2+).
* Lateral Propagation: Automated discovery and infection of mapped 
  SMB/Network drives (T1135).
* Persistence: Registry Run Key hijacking (T1547.001) ensuring 
  survival across system reboots.
* Impact & UI Defacement (T1491):
    - Wallpaper Hijack: Forces a red "SYSTEM LOCKED" background.
    - Ransom Messages: Distributed HTML notes in all folders.
    - Countdown: Terminal-based timer before simulated data wipe.
* Canary Tripwire: Real-time C2 alerts triggered when Honey-pot 
  files (e.g., _ADMIN_PASSWORDS.xlsx) are encrypted or accessed.

3. DEPLOYMENT & EXECUTION
-------------------------
[A] Server Setup:
    1. Install deps: pip install quart cryptography aiosqlite
    2. Run (requires sudo for Port 443): sudo python3 c2_server.py

[B] Client Compilation (EXE Generation):
    1. Install PS2EXE: Install-Module ps2exe -Scope CurrentUser
    2. Compile: 
       Invoke-PS2EXE -InputFile "ApexSim.ps1" -OutputFile "ApexUpdater.exe" -WindowStyle Hidden

[C] Post-Incident Reporting:
    Extract telemetry from the database: python3 apex_report.py

4. INCIDENT RESPONSE (IR) EXERCISE TEMPLATE
-------------------------------------------
Simulation ID: APEX-2026-###
Target Host: [Hostname]

| Phase            | Technique | Alert Triggered? | TTD (Min) |
| :---             | :---      | :---             | :---      |
| Persistence      | T1547.001 | [YES/NO]         | [ ]       |
| Lateral Movement | T1135     | [YES/NO]         | [ ]       |
| Exfiltration     | T1041     | [YES/NO]         | [ ]       |
| Canary Trip      | Honey-pot | [YES/NO]         | [ ]       |
| Encryption       | T1486     | [YES/NO]         | [ ]       |

5. RULES OF ENGAGEMENT (RoE) & SAFETY
-------------------------------------
1. TARGETING: Hard-code $TargetPath to an isolated sandbox.
2. NETWORKING: Use Host-Only/Internal VM networking ONLY.
3. RESTORATION: Run 'ApexSim.ps1 -Mode Decrypt' to revert changes.
4. C2 SECURITY: Use the AES shared key to secure the agent.

6. FULL DISCLAIMER
------------------
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND PERMISSIONED TESTING 
PURPOSES ONLY. Unauthorized use of this tool against systems without 
prior explicit consent is illegal and unethical. The authors assume 
no liability for any data loss, system damage, legal consequences, 
or misuse of the framework. By using this software, you agree to 
operate within the legal boundaries of your jurisdiction.
================================================================