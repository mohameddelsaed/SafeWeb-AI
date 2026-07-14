$ErrorActionPreference = 'Continue'
$env:GOPATH = "d:\My Files\Graduation Project\safeweb-ai\tools\go"
$env:GOBIN  = "d:\My Files\Graduation Project\safeweb-ai\tools\bin"
$env:PATH   = "$env:GOBIN;" + $env:PATH
$BIN = $env:GOBIN

$missing = @()
$checks = @(
    @{name="subfinder"; file="$BIN\subfinder.exe"},
    @{name="httpx";     file="$BIN\httpx.exe"},
    @{name="nuclei";    file="$BIN\nuclei.exe"},
    @{name="nikto";     file="$BIN\nikto.cmd"},
    @{name="eyewitness";file="$BIN\eyewitness.cmd"}
)
foreach ($c in $checks) {
    if (Test-Path $c.file) { Write-Host "[OK]      $($c.name)" -ForegroundColor Green }
    else { Write-Host "[MISSING] $($c.name)" -ForegroundColor Yellow; $missing += $c.name }
}
"MISSING=$($missing -join ',')" | Out-File "$env:TEMP\miss.txt" -Encoding UTF8
