/*
Copyright (c) 2026 José María Micoli
Licensed under the Business Source License 1.1
Change Date: 2033-02-17
Change License: Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

param([string]$RootPath = "C:\SimulationData")
if (!(Test-Path $RootPath)) { New-Item -ItemType Directory -Path $RootPath }
$Extensions = @("docx", "xlsx", "pdf", "jpg", "txt")
for ($i = 1; $i -le 5; $i++) {
    $SubPath = Join-Path $RootPath "Folder_$i"
    New-Item -ItemType Directory -Path $SubPath -Force | Out-Null
    for ($j = 1; $j -le 10; $j++) {
        $FilePath = Join-Path $SubPath "TestFile_$j.$($Extensions | Get-Random)"
        "Apex Pro Simulation Data Content" | Out-File $FilePath
    }
}
"Canary_Admin_Creds=P@ssw0rd123!" | Out-File (Join-Path $RootPath "_ADMIN_PASSWORDS.xlsx")
Write-Host "[+] Setup Complete. Data generated in $RootPath" -ForegroundColor Green