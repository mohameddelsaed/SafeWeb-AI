"""Live scan test script.

This file is intentionally runnable as a standalone diagnostic command and is
kept side-effect free during import so pytest collection does not start scans.
"""

import json
import os
import sys
import time

import django


def main() -> int:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")
    os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
    django.setup()

    from apps.accounts.models import User
    from apps.scanning.engine.orchestrator import ScanOrchestrator
    from apps.scanning.models import Scan, Vulnerability

    user, _ = User.objects.get_or_create(
        email="test@safeweb.ai",
        defaults={"username": "test_scanner", "is_active": True},
    )
    if not user.has_usable_password():
        user.set_password("testpass123")
        user.save()

    scan = Scan.objects.create(
        user=user,
        scan_type="website",
        target="http://testphp.vulnweb.com/",
        depth="medium",
        include_subdomains=False,
        check_ssl=False,
        follow_redirects=True,
        status="pending",
    )
    print(f"\n{'=' * 70}")
    print("  SafeWeb AI - Live Scan Test")
    print(f"  Scan ID : {scan.id}")
    print(f"  Target  : {scan.target}")
    print(f"  Depth   : {scan.depth}")
    print(f"{'=' * 70}\n")

    start = time.time()
    try:
        orchestrator = ScanOrchestrator()
        orchestrator.execute_scan(str(scan.id))
    except Exception as exc:
        print(f"\n[ERROR] Scan failed: {exc}")
        import traceback

        traceback.print_exc()
    elapsed = time.time() - start

    scan.refresh_from_db()
    vulnerabilities = Vulnerability.objects.filter(scan=scan).order_by("-cvss", "-severity")

    print(f"\n{'=' * 70}")
    print("  SCAN RESULTS")
    print(f"{'=' * 70}")
    print(f"  Status   : {scan.status}")
    print(f"  Score    : {scan.score}/100")
    print(f"  Duration : {elapsed:.1f}s")
    print(f"  Pages    : {scan.pages_crawled}")
    print(f"  Requests : {scan.total_requests}")
    print(f"  Findings : {vulnerabilities.count()}")
    if scan.error_message:
        print(f"  Error    : {scan.error_message}")
    print()

    severity_counts = {}
    for vulnerability in vulnerabilities:
        severity_counts[vulnerability.severity] = severity_counts.get(vulnerability.severity, 0) + 1
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(severity, 0)
        if count:
            print(f"  {severity.upper():10s}: {count}")

    print(f"\n{'-' * 70}")
    print("  VULNERABILITY DETAILS")
    print(f"{'-' * 70}")

    for idx, vulnerability in enumerate(vulnerabilities[:30], start=1):
        has_exploit = bool(vulnerability.exploit_data)
        exploit_tag = " [EXPLOITED]" if has_exploit else ""
        print(f"\n  {idx}. [{vulnerability.severity.upper()}] {vulnerability.name}{exploit_tag}")
        print(f"     Category : {vulnerability.category}")
        print(f"     CVSS     : {vulnerability.cvss}")
        print(f"     CWE      : {vulnerability.cwe}")
        print(f"     URL      : {vulnerability.affected_url}")
        print(f"     Verified : {vulnerability.verified}")
        if has_exploit:
            exploit_data = vulnerability.exploit_data
            exploit = exploit_data.get("exploit", {})
            report = exploit_data.get("report", {})
            print(f"     Exploit Success : {exploit.get('success')}")
            print(f"     Exploit Type    : {exploit.get('exploit_type')}")
            print(f"     Impact Proof    : {(exploit.get('impact_proof') or '')[:120]}")
            report_quality = "LLM-enhanced" if report.get("llm_enhanced") else "Template-based"
            print(f"     BB Report       : {report_quality}")
            if exploit.get("extracted_data"):
                data = json.dumps(exploit["extracted_data"], default=str)[:200]
                print(f"     Extracted Data  : {data}")

    if scan.recon_data and "_stats" in scan.recon_data:
        print(f"\n{'-' * 70}")
        print("  PHASE TIMING")
        print(f"{'-' * 70}")
        for phase, seconds in scan.recon_data["_stats"].items():
            print(f"  {phase:20s}: {seconds:.1f}s")

    exploited = [vulnerability for vulnerability in vulnerabilities if vulnerability.exploit_data]
    if exploited:
        print(f"\n{'=' * 70}")
        print(f"  BUG BOUNTY REPORT SAMPLES ({len(exploited)} exploited findings)")
        print(f"{'=' * 70}")
        for vulnerability in exploited[:3]:
            report = vulnerability.exploit_data.get("report", {})
            markdown = report.get("markdown", "")
            if markdown:
                print(f"\n--- {vulnerability.name} ---")
                print(markdown[:800])
                if len(markdown) > 800:
                    print(f"  ... [truncated, {len(markdown)} chars total]")

    print(f"\n{'=' * 70}")
    print(f"  DONE - Scan {scan.id}")
    print(f"{'=' * 70}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
