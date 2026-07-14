# Tool Availability Matrix

| Tool | Capability | Deployment Strategy | Wrapper Strategy |
|------|------------|---------------------|------------------|
| Nuclei | Vulnerability Scanning | Host Binary / Docker | `subprocess.run` |
| Nmap | Port Scanning | Host Binary | `subprocess.run` |
| Subfinder | Subdomain Enumeration | Host Binary | `subprocess.run` |

## Integration Approach
External tools should be invoked via robust Python wrappers (e.g., `ExternalTool` base class) that handle timeouts, retries, and output parsing (JSON preferred where supported).
