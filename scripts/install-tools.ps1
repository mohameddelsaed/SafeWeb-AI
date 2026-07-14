#Requires -Version 5.1
<#
.SYNOPSIS
    Install all SafeWeb-AI bug bounty tools + SecLists.
    Everything is redirected to D:\...\safeweb-ai\tools\ to avoid filling C:.

.DESCRIPTION
    Directory layout under <project>\tools\:
      bin\     -- compiled Go + Cargo binaries (added to PATH)
      go\      -- GOPATH (module cache, pkg, src)
      cargo\   -- CARGO_HOME
      rustup\  -- RUSTUP_HOME
      npm\     -- npm global prefix
      gems\    -- Ruby GEM_HOME

    Python tools go into the project .venv (already on D:).
    SecLists goes to backend\apps\scanning\engine\payloads\data\seclists\.

.EXAMPLE
    .\scripts\install-tools.ps1
    .\scripts\install-tools.ps1 -SkipSecLists
    .\scripts\install-tools.ps1 -SkipGo
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [switch]$SkipSecLists,
    [switch]$SkipGo,
    [switch]$SkipPython,
    [switch]$SkipRuby,
    [switch]$SkipRust,
    [switch]$SkipNode,
    [switch]$SkipNmap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Helpers -----------------------------------------------------------------
function Write-Ok   { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "  [ERR] $msg" -ForegroundColor Red }
function Write-Head { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

function Test-Command {
    param($Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# --- Paths: everything under <project>\tools\ --------------------------------
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolsRoot   = Join-Path $projectRoot 'tools'

$goBinDir    = Join-Path $toolsRoot 'bin'
$goPathDir   = Join-Path $toolsRoot 'go'
$cargoHome   = Join-Path $toolsRoot 'cargo'
$rustupHome  = Join-Path $toolsRoot 'rustup'
$npmPrefix   = Join-Path $toolsRoot 'npm'
$gemHome     = Join-Path $toolsRoot 'gems'

foreach ($d in @($goBinDir, $goPathDir, $cargoHome, $rustupHome, $npmPrefix, $gemHome)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "  Tools root: $toolsRoot" -ForegroundColor DarkCyan

# Set env vars for this session
$env:GOPATH      = $goPathDir
$env:GOBIN       = $goBinDir
$env:GOMODCACHE  = "$goPathDir\pkg\mod"
$env:CARGO_HOME  = $cargoHome
$env:RUSTUP_HOME = $rustupHome
$env:GEM_HOME    = $gemHome
$env:GEM_PATH    = $gemHome

# Add bin dirs to PATH for this session
$extraPaths = @($goBinDir, "$cargoHome\bin", "$npmPrefix\bin", "$gemHome\bin")
foreach ($p in $extraPaths) {
    if ($env:PATH -notlike "*$p*") { $env:PATH += ";$p" }
}

# Persist to user environment so reopened terminals find the tools
[Environment]::SetEnvironmentVariable('GOPATH',      $goPathDir,  'User')
[Environment]::SetEnvironmentVariable('GOBIN',       $goBinDir,   'User')
[Environment]::SetEnvironmentVariable('GOMODCACHE',  "$goPathDir\pkg\mod", 'User')
[Environment]::SetEnvironmentVariable('CARGO_HOME',  $cargoHome,  'User')
[Environment]::SetEnvironmentVariable('RUSTUP_HOME', $rustupHome, 'User')
[Environment]::SetEnvironmentVariable('GEM_HOME',    $gemHome,    'User')
[Environment]::SetEnvironmentVariable('GEM_PATH',    $gemHome,    'User')

$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
foreach ($p in $extraPaths) {
    if ($userPath -notlike "*$p*") { $userPath += ";$p" }
}
[Environment]::SetEnvironmentVariable('PATH', $userPath, 'User')
Write-Ok "Environment variables set -- all tools will install to D:"

# --- Go tools ----------------------------------------------------------------
if (-not $SkipGo) {
    Write-Head "Go-based tools (32 tools)"

    if (-not (Test-Command 'go')) {
        Write-Err "Go is not installed. Install from https://go.dev/dl/ then re-run."
        $SkipGo = $true
    }
}

if (-not $SkipGo) {
    $goTools = [ordered]@{
        'nuclei'      = 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
        'subfinder'   = 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
        'httpx'       = 'github.com/projectdiscovery/httpx/cmd/httpx@latest'
        'katana'      = 'github.com/projectdiscovery/katana/cmd/katana@latest'
        'gau'         = 'github.com/lc/gau/v2/cmd/gau@latest'
        'gospider'    = 'github.com/jaeles-project/gospider@latest'
        'waybackurls' = 'github.com/tomnomnom/waybackurls@latest'
        'ffuf'        = 'github.com/ffuf/ffuf/v2@latest'
        'gf'          = 'github.com/tomnomnom/gf@latest'
        'qsreplace'   = 'github.com/tomnomnom/qsreplace@latest'
        'dalfox'      = 'github.com/hahwul/dalfox/v2@latest'
        'crlfuzz'     = 'github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest'
        'amass'              = 'github.com/owasp-amass/amass/v4/...@master'
        # Phase A — subdomain / recon
        'assetfinder'        = 'github.com/tomnomnom/assetfinder@latest'
        'chaos'              = 'github.com/projectdiscovery/chaos-client/cmd/chaos@latest'
        'asnmap'             = 'github.com/projectdiscovery/asnmap/cmd/asnmap@latest'
        'mapcidr'            = 'github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest'
        'dnsx'               = 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
        'puredns'            = 'github.com/d3mondev/puredns/v2@latest'
        'hakrawler'          = 'github.com/hakluke/hakrawler@latest'
        'getJS'              = 'github.com/003random/getJS@latest'
        'httprobe'           = 'github.com/tomnomnom/httprobe@latest'
        'tlsx'               = 'github.com/projectdiscovery/tlsx/cmd/tlsx@latest'
        # Port scan
        'naabu'              = 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'
        # Phase B — vuln scanners
        'subjack'            = 'github.com/haccer/subjack@latest'
        'SubOver'            = 'github.com/Ice3man543/SubOver@latest'
        # Phase C — secrets
        'trufflehog'         = 'github.com/trufflesecurity/trufflehog/v3@latest'
        'gitleaks'           = 'github.com/zricethezav/gitleaks/v8@latest'
        # Phase D — cloud
        's3scanner'          = 'github.com/sa7mon/s3scanner@latest'
        # Phase E — fuzzing / screenshots
        'gobuster'           = 'github.com/OJ/gobuster/v3@latest'
        'aquatone'           = 'github.com/michenriksen/aquatone@latest'
        # Phase F — OOB
        'interactsh-client'  = 'github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest'
    }

    foreach ($tool in $goTools.Keys) {
        $pkg = $goTools[$tool]
        if (Test-Path "$goBinDir\$tool.exe") {
            Write-Ok "$tool already installed in tools\bin - skipping"
        } elseif (Test-Command $tool) {
            Write-Ok "$tool already on PATH - skipping"
        } else {
            Write-Host "  Installing $tool ..." -NoNewline
            $result = go install -v $pkg 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok " done"
            } else {
                $tail = $result | Select-Object -Last 3 | Out-String
                Write-Err " failed -- $tail"
            }
        }
    }

    if (Test-Command 'nuclei') {
        Write-Host "  Updating Nuclei templates ..." -NoNewline
        nuclei -update-templates 2>&1 | Out-Null
        Write-Ok " done"
    }

    $gfPatterns = "$env:USERPROFILE\.gf"
    if ((Test-Command 'gf') -and (-not (Test-Path "$gfPatterns\xss.json"))) {
        Write-Head "gf Patterns"
        New-Item -ItemType Directory -Force -Path $gfPatterns | Out-Null
        $tmp = "$env:TEMP\gf-patterns"
        git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git $tmp 2>&1 | Out-Null
        Copy-Item "$tmp\*.json" $gfPatterns -Force
        Remove-Item $tmp -Recurse -Force
        Write-Ok "gf patterns installed to $gfPatterns"
    }
}

# --- Python tools (into project .venv) ---------------------------------------
if (-not $SkipPython) {
    Write-Head "Python-based tools (10 pip + 5 git-clone -- installed into .venv)"
    $venvPip = Join-Path $projectRoot '.venv\Scripts\pip.exe'
    if (Test-Path $venvPip) {
        $pip = $venvPip
        Write-Ok "Using project .venv pip: $pip"
    } elseif (Test-Command 'pip') {
        $pip = 'pip'
        Write-Warn "No .venv found -- falling back to global pip"
    } else {
        $pip = $null
        Write-Err "pip not found -- skipping Python tools"
    }

    if ($pip) {
        $pyTools = @(
            'sqlmap', 'commix', 'dirsearch', 'arjun', 'paramspider', 'sslyze', 'dnsrecon',
            # Phase A
            'sublist3r',
            # Phase B
            'ghauri',
            # Phase D
            'cloud-enum'
        )
        foreach ($tool in $pyTools) {
            Write-Host "  pip install $tool ..." -NoNewline
            $result = & $pip install $tool 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok " done"
            } else {
                $tail = $result | Select-Object -Last 2 | Out-String
                Write-Err " failed -- $tail"
            }
        }
    }
}

# --- Git-clone Python tools (with .cmd shims) --------------------------------
if (-not $SkipPython) {
    Write-Head "Git-clone Python tools (xsstrike, tplmap, linkfinder, secretfinder, awsbucketdump)"

    $venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path $venvPython)) { $venvPython = 'python' }

    $cloneTools = @(
        @{ name='xsstrike';     repo='https://github.com/s0md3v/XSStrike.git';           entry='xsstrike.py'     },
        @{ name='tplmap';       repo='https://github.com/epinna/tplmap.git';             entry='tplmap.py'       },
        @{ name='linkfinder';   repo='https://github.com/GerbenJavado/LinkFinder.git';   entry='linkfinder.py'   },
        @{ name='secretfinder'; repo='https://github.com/m4ll0k/SecretFinder.git';       entry='SecretFinder.py' },
        @{ name='AWSBucketDump';repo='https://github.com/jordanpotti/AWSBucketDump.git'; entry='AWSBucketDump.py'}
    )
    foreach ($ct in $cloneTools) {
        $dest = Join-Path $toolsRoot $ct.name
        $shim = Join-Path $goBinDir "$($ct.name).cmd"
        if (Test-Path $dest) {
            Write-Ok "$($ct.name) already cloned -- pulling"
            git -C $dest pull --ff-only 2>&1 | Out-Null
        } else {
            Write-Host "  git clone $($ct.name) ..." -NoNewline
            git clone --depth 1 $ct.repo $dest 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Ok " done" } else { Write-Err " failed" }
        }
        # Install requirements.txt if present
        $req = Join-Path $dest 'requirements.txt'
        if (Test-Path $req) {
            & $venvPython -m pip install -r $req -q 2>&1 | Out-Null
        }
        # Create .cmd shim
        if (-not (Test-Path $shim)) {
            $entryPath = Join-Path $dest $ct.entry
            "@echo off`r`n$venvPython `"$entryPath`" %*" | Set-Content -Path $shim -Encoding ASCII
            Write-Ok "Shim created: $shim"
        }
    }
}

# --- Pre-built binaries (findomain, x8, masscan) ----------------------------
Write-Head "Pre-built binaries"

# findomain
$findomainBin = Join-Path $goBinDir 'findomain.exe'
if (-not (Test-Path $findomainBin) -and -not (Test-Command 'findomain')) {
    Write-Host '  Downloading findomain (latest release) ...' -NoNewline
    try {
        $fdRelease = Invoke-RestMethod 'https://api.github.com/repos/Findomain/Findomain/releases/latest' -TimeoutSec 30
        $fdAsset   = $fdRelease.assets | Where-Object { $_.name -like '*windows*' -or $_.name -like '*x86_64-windows*' } | Select-Object -First 1
        if ($fdAsset) {
            Invoke-WebRequest $fdAsset.browser_download_url -OutFile $findomainBin -ErrorAction Stop
            Write-Ok ' done'
        } else { Write-Warn ' no Windows asset found in release' }
    } catch { Write-Err " failed: $_" }
} else {
    Write-Ok 'findomain already installed'
}

# x8 (parameter discovery — Rust binary, pre-built release)
$x8Bin = Join-Path $goBinDir 'x8.exe'
if (-not (Test-Path $x8Bin) -and -not (Test-Command 'x8')) {
    Write-Host '  Downloading x8 (latest release) ...' -NoNewline
    try {
        $x8Release = Invoke-RestMethod 'https://api.github.com/repos/Sh1Yo/x8/releases/latest' -TimeoutSec 30
        $x8Asset   = $x8Release.assets | Where-Object { $_.name -like '*windows*' -and $_.name -like '*.exe' } | Select-Object -First 1
        if ($x8Asset) {
            Invoke-WebRequest $x8Asset.browser_download_url -OutFile $x8Bin -ErrorAction Stop
            Write-Ok ' done'
        } else { Write-Warn ' no Windows .exe found in release' }
    } catch { Write-Err " failed: $_" }
} else {
    Write-Ok 'x8 already installed'
}

# masscan — Windows needs WSL or a pre-built binary; warn user
if (-not (Test-Command 'masscan')) {
    Write-Warn 'masscan: not installed. On Windows, best approach is WSL (sudo apt install masscan)'
    Write-Warn '         or download from https://github.com/robertdavidgraham/masscan/releases'
} else {
    Write-Ok 'masscan already installed'
}

# --- Nmap --------------------------------------------------------------------
if (-not $SkipNmap) {
    Write-Head "Nmap"
    if (Test-Command 'nmap') {
        Write-Ok "nmap already installed"
    } else {
        Write-Host "  Installing nmap via winget ..." -NoNewline
        winget install --id Insecure.Nmap --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok " done"
        } else {
            Write-Err " winget failed - download from https://nmap.org/download.html"
        }
    }
}

# --- Rust / feroxbuster ------------------------------------------------------
if (-not $SkipRust) {
    Write-Head "Rust-based tools (feroxbuster)"
    if (Test-Path "$cargoHome\bin\feroxbuster.exe") {
        Write-Ok "feroxbuster already installed in tools\cargo\bin"
    } elseif (Test-Command 'feroxbuster') {
        Write-Ok "feroxbuster already on PATH"
    } elseif (Test-Command 'cargo') {
        Write-Host "  cargo install feroxbuster (CARGO_HOME -> D:) ..." -NoNewline
        cargo install feroxbuster 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok " done"
        } else {
            Write-Err " failed"
        }
    } else {
        Write-Warn "cargo not found. Install Rust: winget install Rustlang.Rustup"
        Write-Warn "Then run: rustup default stable; cargo install feroxbuster"
    }

    if (-not (Test-Command 'rustscan')) {
        Write-Warn "rustscan: download the Windows .exe from https://github.com/RustScan/RustScan/releases"
    } else {
        Write-Ok "rustscan already installed"
    }
}

# --- Ruby gems ---------------------------------------------------------------
if (-not $SkipRuby) {
    Write-Head "Ruby-based tools (wpscan, whatweb) -- GEM_HOME -> D:"
    if (Test-Command 'gem') {
        foreach ($g in @('wpscan', 'whatweb')) {
            if (Test-Command $g) {
                Write-Ok "$g already installed"
            } else {
                Write-Host "  gem install $g ..." -NoNewline
                gem install $g 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok " done"
                } else {
                    Write-Err " failed"
                }
            }
        }
    } else {
        Write-Warn "ruby/gem not found. Install Ruby: winget install RubyInstallerTeam.Ruby.3.2"
    }
}

# --- Node.js tools -----------------------------------------------------------
if (-not $SkipNode) {
    Write-Head "Node.js tools (wappalyzer) -- npm prefix -> D:"
    if (Test-Command 'npm') {
        if (Test-Command 'wappalyzer') {
            Write-Ok "wappalyzer already installed"
        } else {
            Write-Host "  npm install -g wappalyzer ..." -NoNewline
            npm install -g --prefix $npmPrefix wappalyzer 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok " done"
            } else {
                Write-Err " failed"
            }
        }
    } else {
        Write-Warn "npm not found. Install Node.js: winget install OpenJS.NodeJS"
    }
}

# --- SecLists ----------------------------------------------------------------
if (-not $SkipSecLists) {
    Write-Head "SecLists wordlists (-> project backend\...)"

    $seclistDir = Join-Path $projectRoot 'backend\apps\scanning\engine\payloads\data\seclists'

    if (Test-Path "$seclistDir\Discovery") {
        Write-Ok "SecLists already installed at $seclistDir"
        Write-Host "  Pulling latest changes ..." -NoNewline
        git -C $seclistDir pull --ff-only 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok " updated"
        } else {
            Write-Warn " pull skipped (offline?)"
        }
    } else {
        if (-not (Test-Command 'git')) {
            Write-Err "git not found - install Git for Windows: winget install Git.Git"
        } else {
            Write-Host "  Shallow-cloning SecLists (~2 GB) ..."
            Write-Host "  Target: $seclistDir"
            New-Item -ItemType Directory -Force -Path (Split-Path $seclistDir) | Out-Null
            git clone --depth 1 https://github.com/danielmiessler/SecLists.git $seclistDir
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "SecLists installed"
            } else {
                Write-Err "Clone failed"
            }
        }
    }
}

# --- Final verification ------------------------------------------------------
Write-Head "Verification"

$allTools = @(
    # Original 25
    'nuclei','subfinder','httpx','katana','gau','gospider','waybackurls',
    'ffuf','gf','qsreplace','dalfox','crlfuzz','amass',
    'nmap','sqlmap','commix','dirsearch','arjun','sslyze','dnsrecon',
    'feroxbuster','wpscan','whatweb','wappalyzer',
    # Phase A — subdomain / recon
    'assetfinder','chaos','asnmap','mapcidr','dnsx','puredns',
    'hakrawler','getJS','httprobe','tlsx',
    # Port scan
    'naabu',
    # Phase B — vuln scanners
    'subjack','SubOver','ghauri','xsstrike','tplmap',
    # Phase C — secrets / links
    'trufflehog','gitleaks','linkfinder','secretfinder',
    # Phase D — cloud
    's3scanner','cloud_enum','AWSBucketDump',
    # Phase E — fuzzing / screenshots
    'gobuster','x8','masscan','aquatone',
    # Phase F — OOB
    'interactsh-client'
)

$ok   = 0
$miss = @()
foreach ($t in $allTools) {
    if ((Test-Command $t) -or (Test-Path "$goBinDir\$t.exe") -or (Test-Path "$cargoHome\bin\$t.exe")) {
        Write-Ok $t
        $ok++
    } else {
        Write-Warn "MISSING: $t"
        $miss += $t
    }
}

$seclistDir2 = Join-Path $projectRoot 'backend\apps\scanning\engine\payloads\data\seclists'
if (Test-Path "$seclistDir2\Discovery") {
    Write-Ok "SecLists wordlists"
    $ok++
} else {
    Write-Warn "MISSING: SecLists"
    $miss += 'SecLists'
}

$total = $allTools.Count + 1
$color = if ($miss.Count -eq 0) { 'Green' } else { 'Yellow' }
Write-Host "`n  $ok / $total tools available" -ForegroundColor $color
if ($miss.Count -gt 0) {
    Write-Host "  Still missing: $($miss -join ', ')" -ForegroundColor Yellow
}

Write-Host "`n  All binaries live in: $toolsRoot" -ForegroundColor DarkCyan