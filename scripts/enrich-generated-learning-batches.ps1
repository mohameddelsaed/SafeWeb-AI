$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$batchDir = 'backend/apps/learn/data/article_batches'
$enc = New-Object System.Text.UTF8Encoding($false)

$audienceByLevel = @{
	foundation = 'Developers and junior AppSec engineers'
	practitioner = 'Security engineers, backend/frontend leads, and pentesters'
	specialist = 'Senior AppSec specialists, platform architects, and red/blue team operators'
}

$whyByCategory = @{
	injection = 'Injection flaws let attacker-controlled input alter trusted execution context, often turning simple input bugs into data compromise or remote command impact.'
	xss = 'Client-side injection breaks browser trust boundaries and enables account takeover, token theft, and transaction manipulation in otherwise hardened backends.'
	api_security = 'API weaknesses are high-leverage because one broken object or workflow check can expose large datasets and privileged operations at machine speed.'
	authentication = 'Authentication design errors cascade across sessions, tokens, and federation paths, allowing attackers to bypass identity assurance without brute force.'
	access_control = 'Access control failures are frequently systemic: one missing ownership check can silently become a cross-tenant data breach and privilege escalation chain.'
	security_headers = 'Browser-side control gaps reduce exploit resistance and can turn medium-severity injection vectors into high-impact account and data compromise.'
	cryptography = 'Cryptographic misuse rarely fails gracefully; weak key lifecycle or validation logic can invalidate trust assumptions across the whole platform.'
	network_security = 'Application-layer network abuse can degrade availability, hide intrusion, and amplify impact when protocol and gateway assumptions are inconsistent.'
	best_practices = 'Security outcomes depend on repeatable engineering practices; weak SDLC controls let known classes of vulnerabilities reappear every release cycle.'
}

$attackByCategory = @{
	injection = 'Attackers probe parser and query boundaries, then escalate from benign payloads to state-changing or exfiltration queries. High-risk paths include dynamic query builders and unsafe command wrappers.'
	xss = 'Attackers identify rendering sinks, bypass contextual encoding assumptions, and chain script execution into credential theft or privileged action replay.'
	api_security = 'Attackers enumerate object identifiers and alternate resolver or endpoint paths, then exploit missing object-level checks and weak abuse controls.'
	authentication = 'Attackers target login, callback, and token lifecycle transitions, abusing weak binding between user intent, session rotation, and token audience checks.'
	access_control = 'Attackers force browse hidden or secondary endpoints, replay authorized requests against unauthorized resources, and pivot through workflow edge cases.'
	security_headers = 'Attackers combine partial browser policy rollouts with injection or clickjacking vectors to maintain script execution and trust transfer paths.'
	cryptography = 'Attackers exploit weak trust validation, stale keys, and permissive cryptographic policy to forge trust artifacts or replay protected messages.'
	network_security = 'Attackers trigger protocol asymmetry, queue pressure, and retry amplification to create denial, concealment windows, and downstream control failures.'
	best_practices = 'Attackers benefit when governance is inconsistent: missing threat modeling, weak code review standards, and sparse verification increase exploit reliability.'
}

$vulnCodeByCategory = @{
	injection = @'
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
rows = db.execute(query)
```
'@
	xss = @'
```tsx
return <div dangerouslySetInnerHTML={{ __html: userHtml }} />
```
'@
	api_security = @'
```python
# Missing object-level authorization
order = Order.objects.get(id=request.GET["id"])
return Response(OrderSerializer(order).data)
```
'@
	authentication = @'
```python
# Accepting ID token as API bearer token
if verify_jwt(token):
    request.user = token["sub"]
```
'@
	access_control = @'
```python
invoice = Invoice.objects.get(id=invoice_id)  # no owner check
return Response(InvoiceSerializer(invoice).data)
```
'@
	security_headers = @'
```http
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
X-Frame-Options: ALLOWALL
```
'@
	cryptography = @'
```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```
'@
	network_security = @'
```nginx
proxy_request_buffering off;
proxy_http_version 1.1;
# no request framing safeguards
```
'@
	best_practices = @'
```yaml
security_review: optional
threat_model: none
release_gate: warnings-only
```
'@
}

$secureCodeByCategory = @{
	injection = @'
```python
rows = db.execute("SELECT * FROM users WHERE email = %s", [email])
```
'@
	xss = @'
```tsx
return <div>{safeText}</div> // escaped by default
```
'@
	api_security = @'
```python
order = get_object_or_404(Order, id=request.GET["id"], user=request.user)
return Response(OrderSerializer(order).data)
```
'@
	authentication = @'
```python
claims = verify_access_token(token, expected_aud="orders-api", expected_iss=ISS)
rotate_session_id(request)
```
'@
	access_control = @'
```python
invoice = get_object_or_404(Invoice, id=invoice_id, owner=request.user)
authorize(request.user, "invoice:read", invoice)
```
'@
	security_headers = @'
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{nonce}'
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
'@
	cryptography = @'
```python
ctx = ssl.create_default_context(cafile=TRUST_BUNDLE)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
```
'@
	network_security = @'
```nginx
http2_max_concurrent_streams 100;
client_body_timeout 10s;
limit_req zone=api burst=20 nodelay;
```
'@
	best_practices = @'
```yaml
security_review: required
threat_model: required
release_gate: fail-on-critical
```
'@
}

$files = Get-ChildItem $batchDir -File | Where-Object { $_.Name -like 'generated_program_batch_*.json' } | Sort-Object Name
$updated = 0

$fallbackVuln = @'
```text
Unsafe pattern example.
```
'@

$fallbackSecure = @'
```text
Secure pattern example.
```
'@

foreach ($f in $files) {
	$arr = Get-Content -Raw $f.FullName | ConvertFrom-Json
	foreach ($a in $arr) {
		$cat = [string]$a.category
		$lvl = [string]$a.difficulty_level
		$aud = if ($audienceByLevel.ContainsKey($lvl)) { $audienceByLevel[$lvl] } else { 'Security engineers and developers' }
		$why = if ($whyByCategory.ContainsKey($cat)) { $whyByCategory[$cat] } else { 'This security topic has direct impact on application trust and production risk.' }
		$atk = if ($attackByCategory.ContainsKey($cat)) { $attackByCategory[$cat] } else { 'Attackers combine reconnaissance and trust-boundary abuse to escalate impact.' }
		$vuln = if ($vulnCodeByCategory.ContainsKey($cat)) { $vulnCodeByCategory[$cat] } else { $fallbackVuln }
		$sec = if ($secureCodeByCategory.ContainsKey($cat)) { $secureCodeByCategory[$cat] } else { $fallbackSecure }

		$depthLine = switch ($lvl) {
			'foundation' { 'Focus on core mechanics, safe defaults, and common implementation mistakes.' }
			'practitioner' { 'Focus on realistic exploit verification, robust remediation, and regression coverage.' }
			'specialist' { 'Focus on multi-step attack chaining, architectural tradeoffs, and high-fidelity detection engineering.' }
			default { 'Focus on practical remediation and operational resilience.' }
		}

		$refs = @($a.references)
		$refsText = ''
		$i = 1
		foreach ($r in $refs) {
			$refsText += "$i. $r`n"
			$i++
		}
		if ([string]::IsNullOrWhiteSpace($refsText)) {
			$refsText = "1. https://owasp.org/Top10/2025/`n2. https://owasp.org/www-project-web-security-testing-guide/v42/`n"
		}

		$owaspRefs = @($a.owasp_refs) -join '; '
		$cweRefs = @($a.cwe_ids) -join ', '

		$content = @"
# $($a.title)

## Audience and Level
- Target audience: $aud
- Difficulty: $lvl
- Estimated read time: $($a.read_time) minutes

## Why This Matters
$why

## Threat Model Snapshot
- Assets at risk: sensitive data, session and token trust, critical business workflows
- Entry points: user-controlled inputs, API boundaries, auth transitions, browser execution surfaces
- Trust boundaries: client to backend, gateway to service, identity provider to resource server
- Typical attacker goals: unauthorized access, data exfiltration, privilege escalation, resilience degradation

## Attack Mechanics
$atk
$depthLine

## Vulnerable Patterns
$vuln

## Detection and Verification
- Manual checks: enumerate attackable paths and validate policy enforcement at object and action boundaries
- Automated checks: include negative authorization and malformed input tests in CI
- Logging indicators: repeated denied actions, abnormal token reuse, parser mismatch or validation failures
- False-positive control: require evidence of unauthorized data access or state-changing behavior

## Secure Implementation
$sec

## Hardening Checklist
- [x] Strict input validation and schema enforcement
- [x] Context-aware output handling and browser policy controls
- [x] Explicit authentication and authorization checks at every sensitive boundary
- [x] Abuse controls: rate limits, anomaly detection, and replay safeguards
- [x] Security telemetry with actionable incident triage context

## Mapping and References
- OWASP: $owaspRefs
- CWE: $cweRefs
- WSTG: OWASP WSTG v4.2
- ASVS: OWASP ASVS v5

## Source Notes
Rewritten synthesis from authoritative sources. No verbatim source copying.

## References
$refsText
"@

		$a.content = $content.Trim() + "`n"
		$a.status = 'review'
		$a.is_published = $false
		if (-not $a.source_count -or [int]$a.source_count -lt $refs.Count) {
			$a.source_count = $refs.Count
		}
		$updated++
	}

	$json = $arr | ConvertTo-Json -Depth 14
	[System.IO.File]::WriteAllText($f.FullName, $json, $enc)
}

Write-Output ("updated_articles={0}" -f $updated)
Write-Output ("updated_files={0}" -f $files.Count)
