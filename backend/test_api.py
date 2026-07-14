"""Test the full API pipeline: auth -> scan detail -> verify exploit_data in response.

This file is a runnable script. Keeping all execution inside main() prevents
pytest collection from triggering live HTTP calls.
"""

import json
import sys

import requests


BASE_URL = "http://localhost:8000"


def main() -> int:
    print("=" * 60)
    print("  SafeWeb AI - API Pipeline Test")
    print("=" * 60)

    print("\n[1] Getting JWT token...")
    resp = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={"email": "test@safeweb.ai", "password": "testpass123"},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"  ERROR: Login failed ({resp.status_code}): {resp.text[:200]}")
        return 1

    data_login = resp.json()
    token = (data_login.get("tokens") or data_login).get("access", "")
    print(f"  OK - Token: {token[:40]}...")
    headers = {"Authorization": f"Bearer {token}"}

    print("\n[2] Listing scans...")
    resp = requests.get(f"{BASE_URL}/api/scans/", headers=headers, timeout=10)
    print(f"  Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"  ERROR: {resp.text[:300]}")
        return 1

    scans = resp.json()
    items = scans.get("results", scans) if isinstance(scans, dict) else scans
    print(f"  Scans in list: {len(items)}")
    for scan in items[:3]:
        print(
            "    [{status}] {scan_id} - {target} ({score} pts, {duration}s)".format(
                status=scan.get("status", "?"),
                scan_id=scan.get("id", ""),
                target=scan.get("target", ""),
                score=scan.get("score", 0),
                duration=scan.get("duration", 0),
            )
        )

    if not items:
        print("\n  No scans found - scan may still be running")
        return 0

    scan_id = items[0]["id"]
    print(f"\n[3] Getting scan detail for {scan_id}...")
    resp = requests.get(f"{BASE_URL}/api/scan/{scan_id}/", headers=headers, timeout=15)
    print(f"  Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"  ERROR: {resp.text[:300]}")
        return 1

    data = resp.json()
    print(f"  Scan status: {data.get('status')}")
    print(f"  Score: {data.get('score')}/100")
    print(f"  Duration: {data.get('duration')}s")
    print(f"  Pages crawled: {data.get('pages_crawled')}")
    print(f"  Total requests: {data.get('total_requests')}")
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"  Vulnerabilities in API: {len(vulnerabilities)}")

    print("\n[4] Checking vulnerability structure...")
    has_exploit_data_key = (
        all("exploit_data" in vuln for vuln in vulnerabilities[:3]) if vulnerabilities else None
    )
    print(f"  exploit_data key present in all vulns: {has_exploit_data_key}")

    exploited = [vuln for vuln in vulnerabilities if vuln.get("exploit_data")]
    verified = [vuln for vuln in vulnerabilities if vuln.get("verified")]
    print(f"  Verified vulns: {len(verified)}")
    print(f"  Vulns with exploit_data: {len(exploited)}")

    severity_breakdown = {}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "?")
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    print(f"  Severity breakdown: {json.dumps(severity_breakdown)}")

    print("\n[5] Top vulns:")
    for vuln in sorted(
        vulnerabilities, key=lambda item: (item.get("cvss", 0) or 0), reverse=True
    )[:10]:
        exploit_tag = "[E]" if vuln.get("exploit_data") else "[ ]"
        verified_tag = "[V]" if vuln.get("verified") else "[ ]"
        short_url = (vuln.get("affected_url") or "-")[:45]
        print(
            f"  {exploit_tag}{verified_tag} "
            f"[{vuln.get('severity', '?').upper():8s}] "
            f"{vuln.get('name', '')[:50]:50s} | {short_url}"
        )

    if exploited:
        print("\n[6] Exploit data sample:")
        vuln = exploited[0]
        exploit_data = vuln["exploit_data"]
        exploit = exploit_data.get("exploit", {}) if exploit_data else {}
        report = exploit_data.get("report", {}) if exploit_data else {}
        print(f"  Vuln: {vuln['name']}")
        print(f"  exploit.success: {exploit.get('success')}")
        print(f"  exploit.type: {exploit.get('exploit_type')}")
        print(f"  exploit.poc (truncated): {str(exploit.get('poc', ''))[:100]}")
        print(f"  exploit.steps count: {len(exploit.get('steps', []))}")
        print(f"  report.markdown (chars): {len(report.get('markdown', ''))}")
        print(f"  report.llm_enhanced: {report.get('llm_enhanced')}")
        print()
        print("  Full pipeline verified: scan -> DB -> API -> exploit_data present in response")
    else:
        print("\n[6] No exploit data yet")
        print("  (Scan may still be running or no verified high/critical vulns found)")
        tester_results = data.get("tester_results") or []
        passed = [
            tester
            for tester in tester_results
            if tester.get("status") == "passed" and tester.get("findingsCount", 0) > 0
        ]
        print(f"  Testers with findings: {[tester['testerName'] for tester in passed[:5]]}")

    print("\n[7] Frontend compatibility check:")
    if vulnerabilities:
        first_vulnerability = vulnerabilities[0]
        required_frontend_keys = [
            "id",
            "name",
            "severity",
            "category",
            "description",
            "impact",
            "remediation",
            "cwe",
            "cvss",
            "affected_url",
            "evidence",
            "is_false_positive",
            "verified",
            "false_positive_score",
            "attack_chain",
            "exploit_data",
        ]
        missing = [key for key in required_frontend_keys if key not in first_vulnerability]
        if missing:
            print(f"  MISSING KEYS: {missing}")
        else:
            print(f"  All {len(required_frontend_keys)} required frontend keys present")

        if exploited:
            exploit_data = exploited[0]["exploit_data"]
            exploit = exploit_data.get("exploit", {})
            report = exploit_data.get("report", {})
            ts_exploit_keys = [
                "success",
                "exploit_type",
                "extracted_data",
                "poc",
                "steps",
                "impact_proof",
            ]
            ts_report_keys = ["markdown", "structured", "llm_enhanced"]
            missing_exploit_keys = [key for key in ts_exploit_keys if key not in exploit]
            missing_report_keys = [key for key in ts_report_keys if key not in report]
            print(f"  exploit TS interface keys missing: {missing_exploit_keys or 'none'}")
            print(f"  report TS interface keys missing: {missing_report_keys or 'none'}")

    print("\n" + "=" * 60)
    print("  API TEST COMPLETE")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
