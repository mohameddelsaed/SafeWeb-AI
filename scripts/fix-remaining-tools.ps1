$ErrorActionPreference = 'Stop'
$goBinDir   = "d:\My Files\Graduation Project\safeweb-ai\tools\bin"
$toolsRoot  = "d:\My Files\Graduation Project\safeweb-ai\tools"
$python     = "d:\My Files\Graduation Project\safeweb-ai\.venv\Scripts\python.exe"
$pip        = "d:\My Files\Graduation Project\safeweb-ai\.venv\Scripts\pip.exe"

# ─────────────────────────────────────────────────────────────
# 1. trufflehog — pre-built Windows binary
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== trufflehog ===" -ForegroundColor Cyan
$thBin = "$goBinDir\trufflehog.exe"
if (-not (Test-Path $thBin)) {
    try {
        $rel   = (Invoke-WebRequest 'https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest' -UseBasicParsing).Content | ConvertFrom-Json
        $asset = $rel.assets | Where-Object { $_.name -like '*windows_amd64*' } | Select-Object -First 1
        $tmp   = "$env:TEMP\trufflehog.tar.gz"
        Write-Host "  Downloading $($asset.name) ..."
        Invoke-WebRequest $asset.browser_download_url -OutFile $tmp -UseBasicParsing
        tar -xzf $tmp -C $goBinDir trufflehog.exe 2>&1 | Out-Null
        Remove-Item $tmp -Force
        if (Test-Path $thBin) { Write-Host "  [OK] trufflehog.exe" -ForegroundColor Green }
        else                  { Write-Host "  [!!] trufflehog.exe not found after extract" -ForegroundColor Yellow }
    } catch { Write-Host "  [ERR] $_" -ForegroundColor Red }
} else { Write-Host "  [OK] already installed" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────
# 2. aquatone — pre-built Windows binary
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== aquatone ===" -ForegroundColor Cyan
$aqBin = "$goBinDir\aquatone.exe"
if (-not (Test-Path $aqBin)) {
    try {
        $rel   = (Invoke-WebRequest 'https://api.github.com/repos/michenriksen/aquatone/releases/latest' -UseBasicParsing).Content | ConvertFrom-Json
        $asset = $rel.assets | Where-Object { $_.name -like '*windows*' -and $_.name -like '*.zip' } | Select-Object -First 1
        $tmp   = "$env:TEMP\aquatone.zip"
        Write-Host "  Downloading $($asset.name) ..."
        Invoke-WebRequest $asset.browser_download_url -OutFile $tmp -UseBasicParsing
        Expand-Archive $tmp -DestinationPath "$env:TEMP\aquatone_extract" -Force
        $exe = Get-ChildItem "$env:TEMP\aquatone_extract" -Filter "aquatone.exe" -Recurse | Select-Object -First 1
        if ($exe) {
            Copy-Item $exe.FullName $aqBin -Force
            Write-Host "  [OK] aquatone.exe" -ForegroundColor Green
        } else { Write-Host "  [!!] aquatone.exe not found in zip" -ForegroundColor Yellow }
        Remove-Item $tmp, "$env:TEMP\aquatone_extract" -Recurse -Force
    } catch { Write-Host "  [ERR] $_" -ForegroundColor Red }
} else { Write-Host "  [OK] already installed" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────
# 3. ghauri — git clone + shim
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== ghauri ===" -ForegroundColor Cyan
$ghauriDir  = "$toolsRoot\ghauri"
$ghauriShim = "$goBinDir\ghauri.cmd"
if (-not (Test-Path $ghauriDir)) {
    git clone --depth 1 https://github.com/r0oth3x49/ghauri.git $ghauriDir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "  [OK] cloned" -ForegroundColor Green }
    else                     { Write-Host "  [ERR] clone failed" -ForegroundColor Red }
} else {
    Write-Host "  [OK] already cloned" -ForegroundColor Green
    git -C $ghauriDir pull --ff-only 2>&1 | Out-Null
}
if (Test-Path "$ghauriDir\requirements.txt") {
    Write-Host "  Installing requirements..."
    & $pip install -r "$ghauriDir\requirements.txt" -q 2>&1 | Out-Null
}
if (-not (Test-Path $ghauriShim)) {
    "@echo off`r`n`"$python`" `"$ghauriDir\ghauri.py`" %*" | Set-Content $ghauriShim -Encoding ASCII
    Write-Host "  [OK] shim created" -ForegroundColor Green
} else { Write-Host "  [OK] shim already exists" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────
# 4. cloud_enum — git clone + shim
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== cloud_enum ===" -ForegroundColor Cyan
$ceDir  = "$toolsRoot\cloud_enum"
$ceShim = "$goBinDir\cloud_enum.cmd"
if (-not (Test-Path $ceDir)) {
    git clone --depth 1 https://github.com/initstring/cloud_enum.git $ceDir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "  [OK] cloned" -ForegroundColor Green }
    else                     { Write-Host "  [ERR] clone failed" -ForegroundColor Red }
} else {
    Write-Host "  [OK] already cloned" -ForegroundColor Green
    git -C $ceDir pull --ff-only 2>&1 | Out-Null
}
if (Test-Path "$ceDir\requirements.txt") {
    Write-Host "  Installing requirements..."
    & $pip install -r "$ceDir\requirements.txt" -q 2>&1 | Out-Null
}
if (-not (Test-Path $ceShim)) {
    "@echo off`r`n`"$python`" `"$ceDir\cloud_enum.py`" %*" | Set-Content $ceShim -Encoding ASCII
    Write-Host "  [OK] shim created" -ForegroundColor Green
} else { Write-Host "  [OK] shim already exists" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────
# 5. x8 — pre-built Windows binary (asset: x86-windown-x8.zip)
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== x8 ===" -ForegroundColor Cyan
$x8Bin = "$goBinDir\x8.exe"
if (-not (Test-Path $x8Bin)) {
    try {
        $rel   = (Invoke-WebRequest 'https://api.github.com/repos/Sh1Yo/x8/releases/latest' -UseBasicParsing).Content | ConvertFrom-Json
        # The Windows asset is named "x86-windown-x8.zip" (typo in upstream)
        $asset = $rel.assets | Where-Object { $_.name -like '*win*' -and $_.name -like '*.zip' } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like '*.zip' } | Select-Object -First 1 }
        if ($asset) {
            $tmp   = "$env:TEMP\x8.zip"
            Write-Host "  Downloading $($asset.name) ..."
            Invoke-WebRequest $asset.browser_download_url -OutFile $tmp -UseBasicParsing
            Expand-Archive $tmp -DestinationPath "$env:TEMP\x8_extract" -Force
            $exe = Get-ChildItem "$env:TEMP\x8_extract" -Recurse | Where-Object { $_.Name -match '^x8(\.exe)?$' } | Select-Object -First 1
            if ($exe) {
                $dest = if ($exe.Name -notmatch '\.exe$') { "$goBinDir\x8.exe" } else { $x8Bin }
                Copy-Item $exe.FullName $dest -Force
                Write-Host "  [OK] x8.exe" -ForegroundColor Green
            } else {
                # List what's in the zip so we can debug
                Write-Host "  [!!] no x8 binary found; zip contents:" -ForegroundColor Yellow
                Get-ChildItem "$env:TEMP\x8_extract" -Recurse | ForEach-Object { Write-Host "       $_" }
            }
            Remove-Item $tmp, "$env:TEMP\x8_extract" -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [!!] no Windows zip asset found in release" -ForegroundColor Yellow
            $rel.assets.name
        }
    } catch { Write-Host "  [ERR] $_" -ForegroundColor Red }
} else { Write-Host "  [OK] already installed" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────
# 6. masscan — SKIPPED (no native Windows binary)
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== masscan ===" -ForegroundColor DarkGray
Write-Host "  [SKIP] masscan requires WSL/Linux — skipped per user request" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────
# Final verification
# ─────────────────────────────────────────────────────────────
Write-Host "`n=== Final check ===" -ForegroundColor Cyan
$checks = @{
    "trufflehog"  = "$goBinDir\trufflehog.exe"
    "aquatone"    = "$goBinDir\aquatone.exe"
    "ghauri"      = "$goBinDir\ghauri.cmd"
    "cloud_enum"  = "$goBinDir\cloud_enum.cmd"
    "x8"          = "$goBinDir\x8.exe"
    "masscan"     = "SKIPPED"
}
$ok = 0; $fail = 0
foreach ($name in $checks.Keys | Sort-Object) {
    $p = $checks[$name]
    if ($p -eq "SKIPPED") { Write-Host "  [SKIP] $name" -ForegroundColor DarkGray; continue }
    if (Test-Path $p) { Write-Host "  [OK]   $name" -ForegroundColor Green; $ok++ }
    else              { Write-Host "  [!!]   $name  ($p)" -ForegroundColor Yellow; $fail++ }
}
Write-Host "`n  $ok / $($ok+$fail) installed (masscan skipped)" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
