#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Ok   { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "  [ERR] $msg" -ForegroundColor Red }
function Write-Head { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Test-Cmd   { param($n) return $null -ne (Get-Command $n -ErrorAction SilentlyContinue) }

$projectRoot = Split-Path -Parent $PSScriptRoot
$toolsBin    = Join-Path $projectRoot 'tools\bin'
$venvScripts = Join-Path $projectRoot '.venv\Scripts'

# Ensure tools\bin and venv\Scripts are in PATH for this session
foreach ($p in @($toolsBin, $venvScripts)) {
    if ($env:PATH -notlike "*$p*") { $env:PATH += ";$p" }
}

# Helper: get latest GitHub release asset URL
function Get-GHAssetUrl {
    param($Repo, $Pattern)
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" `
        -Headers @{Accept='application/vnd.github.v3+json'} -UserAgent 'SafeWebAI'
    $asset = $rel.assets | Where-Object { $_.name -like $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "No asset matching '$Pattern' in $Repo releases" }
    return $asset.browser_download_url, $asset.name
}

function Download-Extract {
    param($Url, $DestBin, $ExeName)
    $zip = "$env:TEMP\dl_$ExeName.zip"
    $ext = "$env:TEMP\dl_$ExeName"
    Write-Host "  Downloading ..." -NoNewline
    Invoke-WebRequest $Url -OutFile $zip -UseBasicParsing
    Write-Host " extracting ..." -NoNewline
    Expand-Archive $zip $ext -Force
    $exe = Get-ChildItem $ext -Filter "$ExeName.exe" -Recurse | Select-Object -First 1
    if ($exe) {
        Copy-Item $exe.FullName (Join-Path $DestBin "$ExeName.exe") -Force
        Write-Ok " done -> $DestBin\$ExeName.exe"
    } else {
        Write-Err " $ExeName.exe not found in archive"
    }
    Remove-Item $zip, $ext -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# 1. katana (pre-built binary from GitHub)
# ============================================================
Write-Head "katana (pre-built)"
if (Test-Path "$toolsBin\katana.exe") {
    Write-Ok "katana already in tools\bin"
} else {
    try {
        $url, $name = Get-GHAssetUrl 'projectdiscovery/katana' '*windows_amd64.zip'
        Download-Extract $url $toolsBin 'katana'
    } catch { Write-Err "katana: $_" }
}

# ============================================================
# 2. amass (pre-built binary from GitHub)
# ============================================================
Write-Head "amass (pre-built)"
if (Test-Path "$toolsBin\amass.exe") {
    Write-Ok "amass already in tools\bin"
} else {
    try {
        $url, $name = Get-GHAssetUrl 'owasp-amass/amass' '*windows_amd64.zip'
        Download-Extract $url $toolsBin 'amass'
    } catch { Write-Err "amass: $_" }
}

# ============================================================
# 3. feroxbuster (pre-built binary from GitHub)
# ============================================================
Write-Head "feroxbuster (pre-built)"
if (Test-Path "$toolsBin\feroxbuster.exe") {
    Write-Ok "feroxbuster already in tools\bin"
} else {
    try {
        # Try zip first, then bare exe
        try {
            $url, $name = Get-GHAssetUrl 'epi052/feroxbuster' '*windows*.zip'
            Download-Extract $url $toolsBin 'feroxbuster'
        } catch {
            $url, $name = Get-GHAssetUrl 'epi052/feroxbuster' '*windows*.exe'
            Write-Host "  Downloading $name ..." -NoNewline
            Invoke-WebRequest $url -OutFile "$toolsBin\feroxbuster.exe" -UseBasicParsing
            Write-Ok " done"
        }
    } catch { Write-Err "feroxbuster: $_" }
}

# ============================================================
# 4. nmap (portable zip from nmap.org)
# ============================================================
Write-Head "nmap (portable)"
if (Test-Cmd 'nmap') {
    Write-Ok "nmap already on PATH"
} elseif (Test-Path "$toolsBin\nmap.exe") {
    Write-Ok "nmap already in tools\bin"
} else {
    try {
        $zip = "$env:TEMP\nmap.zip"
        $ext = "$env:TEMP\nmap-ext"
        Write-Host "  Downloading nmap portable zip ..." -NoNewline
        Invoke-WebRequest 'https://nmap.org/dist/nmap-7.95-win32.zip' -OutFile $zip -UseBasicParsing
        Write-Host " extracting ..." -NoNewline
        Expand-Archive $zip $ext -Force
        $dir = Get-ChildItem $ext -Directory | Select-Object -First 1
        if ($dir) {
            Copy-Item "$($dir.FullName)\*" $toolsBin -Force -Recurse
            Write-Ok " done"
        }
        Remove-Item $zip, $ext -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Write-Err "nmap: $_" }
}

# ============================================================
# 5. Python tools -- verify in .venv\Scripts
# ============================================================
Write-Head "Python tools (venv verify)"
$pip = Join-Path $venvScripts 'pip.exe'
foreach ($tool in @('sqlmap','commix','sslyze','dnsrecon')) {
    $exe = Join-Path $venvScripts "$tool.exe"
    if (Test-Path $exe) {
        Write-Ok "$tool found at $exe"
    } else {
        Write-Host "  Re-installing $tool into .venv ..." -NoNewline
        & $pip install $tool --quiet 2>&1 | Out-Null
        if (Test-Path $exe) { Write-Ok " done" } else { Write-Warn " installed but no .exe wrapper (invokable via: python -m $tool)" }
    }
}

# ============================================================
# 6. wappalyzer -- fix npm global bin path
# ============================================================
Write-Head "wappalyzer"
$npmPrefix = Join-Path $projectRoot 'tools\npm'
# On Windows, npm global installs go to <prefix>, not <prefix>\bin
foreach ($p in @($npmPrefix, "$npmPrefix\bin")) {
    if ($env:PATH -notlike "*$p*") { $env:PATH += ";$p" }
}
if (Test-Cmd 'wappalyzer') {
    Write-Ok "wappalyzer on PATH"
} else {
    # Check for wappalyzer cmd/js in npm prefix
    $found = Get-ChildItem $npmPrefix -Filter 'wappalyzer*' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        Write-Ok "wappalyzer present at $($found.FullName) (invoke as: node $($found.FullName))"
    } else {
        Write-Host "  npm install -g wappalyzer ..." -NoNewline
        $env:npm_config_prefix = $npmPrefix
        npm install -g wappalyzer 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Ok " done" } else { Write-Err " failed" }
    }
}

# ============================================================
# 7. Ruby tools (wpscan, whatweb) -- install Ruby if needed
# ============================================================
Write-Head "Ruby + wpscan + whatweb"
$rubyBin = Join-Path $projectRoot 'tools\ruby\bin'
if ($env:PATH -notlike "*$rubyBin*") { $env:PATH += ";$rubyBin" }

if (-not (Test-Cmd 'ruby')) {
    Write-Host "  Downloading RubyInstaller ..." -NoNewline
    try {
        $rel = Invoke-RestMethod 'https://api.github.com/repos/oneclick/rubyinstaller2/releases/latest' -UserAgent 'SafeWebAI'
        $asset = $rel.assets | Where-Object { $_.name -like 'rubyinstaller-*-x64.exe' -and $_.name -notlike '*devkit*' } | Select-Object -First 1
        if (-not $asset) {
            $asset = $rel.assets | Where-Object { $_.name -like 'rubyinstaller-*-x64.exe' } | Select-Object -First 1
        }
        $rubyInstaller = "$env:TEMP\rubyinstaller.exe"
        Invoke-WebRequest $asset.browser_download_url -OutFile $rubyInstaller -UseBasicParsing
        Write-Host " installing silently ..." -NoNewline
        $rubyDir = Join-Path $projectRoot 'tools\ruby'
        Start-Process $rubyInstaller -ArgumentList "/verysilent /dir=`"$rubyDir`" /tasks=`"`"" -Wait
        Write-Ok " Ruby installed to $rubyDir"
        Remove-Item $rubyInstaller -Force -ErrorAction SilentlyContinue
    } catch { Write-Err "Ruby install failed: $_"; Write-Warn "Install manually from https://rubyinstaller.org/downloads/" }
}

if (Test-Cmd 'gem') {
    foreach ($gem in @('wpscan','whatweb')) {
        if (Test-Cmd $gem) {
            Write-Ok "$gem already installed"
        } else {
            Write-Host "  gem install $gem --no-document ..." -NoNewline
            gem install $gem --no-document 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Ok " done" } else { Write-Err " failed" }
        }
    }
} else {
    Write-Warn "gem still not on PATH after Ruby install. Open a new terminal and re-run: gem install wpscan whatweb"
}

# ============================================================
# Final verification
# ============================================================
Write-Head "Final Verification"
$targets = @('katana','amass','nmap','sqlmap','commix','sslyze','dnsrecon','feroxbuster','wpscan','whatweb','wappalyzer')
$ok = 0; $miss = @()
foreach ($t in $targets) {
    if (Test-Cmd $t) { Write-Ok $t; $ok++ } else { Write-Warn "still missing: $t"; $miss += $t }
}
Write-Host "`n  $ok / $($targets.Count) remaining tools now available" -ForegroundColor $(if ($miss.Count -eq 0){'Green'}else{'Yellow'})
if ($miss.Count -gt 0) { Write-Host "  Missing: $($miss -join ', ')" -ForegroundColor Yellow }