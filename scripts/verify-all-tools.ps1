$goBinDir  = 'd:\My Files\Graduation Project\safeweb-ai\tools\bin'
$cargoHome = 'd:\My Files\Graduation Project\safeweb-ai\tools\cargo'

function Test-Tool($t) {
    (Get-Command $t -ErrorAction SilentlyContinue) -or
    (Test-Path "$goBinDir\$t.exe") -or
    (Test-Path "$goBinDir\$t.cmd") -or
    (Test-Path "$cargoHome\bin\$t.exe")
}

$allTools = @(
    'nuclei','subfinder','httpx','katana','gau','gospider','waybackurls',
    'ffuf','gf','qsreplace','dalfox','crlfuzz','amass',
    'nmap','sqlmap','commix','dirsearch','arjun','sslyze','dnsrecon',
    'feroxbuster','wpscan','whatweb','wappalyzer',
    'assetfinder','chaos','asnmap','mapcidr','dnsx','puredns',
    'hakrawler','getJS','httprobe','tlsx',
    'naabu',
    'subjack','SubOver','ghauri','xsstrike','tplmap',
    'trufflehog','gitleaks','linkfinder','secretfinder',
    's3scanner','cloud_enum','AWSBucketDump',
    'gobuster','x8','aquatone',
    'interactsh-client',
    'findomain'
)
$ok   = 0
$miss = @()
foreach ($t in $allTools) {
    if (Test-Tool $t) { Write-Host "  [OK]  $t" -ForegroundColor Green; $ok++ }
    else              { Write-Host "  [!!]  $t" -ForegroundColor Yellow; $miss += $t }
}

Write-Host ""
Write-Host "  $ok / $($allTools.Count) tools OK  (masscan skipped)" -ForegroundColor Cyan
if ($miss.Count -gt 0) {
    Write-Host "  Still missing: $($miss -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "  All tools accounted for!" -ForegroundColor Green
}
