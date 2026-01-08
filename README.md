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
================================================================
Apex Pro is a high-fidelity adversary emulation tool designed to 
replicate the behaviors of modern ransomware families. It serves 
to validate detection pipelines, EDR efficacy, and IR readiness.

================================================================
2. FEATURES ARCHITECTURE
================================================================
* Robust Cryptography: AES-256-CBC with unique IVs prepended to 
  each file. Uses .NET crypto providers for high entropy.
* Multi-Victim C2: Asynchronous Python backend using Quart and 
  SQLite3 for scalable, persistent victim tracking.
* Stealth Exfiltration: Metadata manifests are AES-encrypted 
  locally before being tunneled through HTTPS (TLS 1.2+).
* Lateral Propagation: Scans and infects mapped SMB/Network 
  drives (Z:, S:, etc.) automatically (T1135).
* Persistence: Registry Run Key hijacking (T1547.001) ensuring 
  survival across system reboots.
* Real-time Alerting: C2 notifies operator instantly when 
  specifically tagged 'Canary' files are accessed.
* Visual Impact & UI Defacement (T1491):
    - Wallpaper Hijack: Forces a red "System Locked" background.
    - Distributed Ransom Notes: Drops custom HTML instructions 
      in every directory containing encrypted files.
    - Destructive Countdown: Terminal-based real-time timer 
      simulating the window before permanent data deletion.

================================================================
3. COMPILATION & BYPASS PROCEDURE
================================================================
To evade basic script-block monitoring, compile to EXE:
1. Install PS2EXE: Install-Module ps2exe -Scope CurrentUser
2. Compile: Invoke-PS2EXE -InputFile "ApexSim.ps1" -OutputFile "ApexUpdater.exe" -WindowStyle Hidden

================================================================
4. INCIDENT RESPONSE (IR) EXERCISE TEMPLATE
================================================================
Simulation ID: APEX-2026-###
Target Host: [Victim Hostname]

| Phase            | Technique | Alert Triggered? | TTD (Min) |
|------------------|-----------|------------------|-----------|
| Persistence      | T1547.001 | [YES/NO]         | [ ]       |
| Exfiltration     | T1041     | [YES/NO]         | [ ]       |
| Canary Trip      | Honey-pot | [YES/NO]         | [ ]       |
| Encryption       | T1486     | [YES/NO]         | [ ]       |

================================================================
5. RULES OF ENGAGEMENT (RoE) & SAFETY
================================================================
1. TARGETING: Hard-code $TargetPath to an isolated directory.
2. NETWORKING: Use Host-Only/Internal VM networking ONLY.
3. CANARY SETUP: Place '_ADMIN_PASSWORDS.xlsx' in target folder.
4. RESTORATION: Run 'ApexSim.ps1 -Mode Decrypt' to clean Registry.

================================================================
6. DISCLAIMER
================================================================
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND PERMISSIONED TESTING 
ONLY. UNAUTHORIZED USE IS ILLEGAL. THE AUTHORS ASSUME NO LIABILITY 
FOR DATA LOSS, LEGAL CONSEQUENCES, OR DAMAGES.
================================================================