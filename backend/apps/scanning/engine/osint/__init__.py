"""
OSINT & External Intelligence Integration.

Provides modules for gathering intelligence from external sources:
- Shodan: Exposed ports, services, vulnerabilities
- Censys: Certificate search, host enumeration
- Wayback Machine: Historical URLs via CDX API
- VirusTotal: Subdomain enumeration, domain reputation
- GitHub: Leaked secrets in public repositories

Each module is optional — runs only if its API key is configured.
All external API calls are made with timeouts and error handling.
"""
