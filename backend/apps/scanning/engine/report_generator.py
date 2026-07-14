"""
PDF and report generation for scan results.
Phase 17: added HTML report, SARIF report, and PoC integration.
"""
import io
import csv
import json
import logging
import html as html_module
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_json_report(scan) -> str:
    """Generate JSON export of scan results."""
    from apps.scanning.serializers import ScanDetailSerializer
    serializer = ScanDetailSerializer(scan)
    return json.dumps(serializer.data, indent=2, default=str)


def generate_csv_report(scan) -> str:
    """Generate CSV export of vulnerability data."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        'Name', 'Severity', 'Category', 'CWE', 'CVSS',
        'Affected URL', 'Description', 'Impact', 'Remediation',
    ])

    for vuln in scan.vulnerabilities.all():
        writer.writerow([
            vuln.name,
            vuln.severity,
            vuln.category,
            vuln.cwe or '',
            vuln.cvss or '',
            vuln.affected_url or '',
            vuln.description,
            vuln.impact,
            vuln.remediation,
        ])

    return output.getvalue()


def generate_pdf_report(scan) -> bytes:
    """Generate PDF report of scan results."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, mm
        from reportlab.lib.colors import HexColor
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib import colors
    except ImportError:
        logger.error('reportlab not installed — PDF generation unavailable')
        raise ImportError('reportlab is required for PDF export')

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=25 * mm,
        leftMargin=25 * mm,
        topMargin=30 * mm,
        bottomMargin=25 * mm,
    )

    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=HexColor('#1a1a2e'),
        spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=HexColor('#16213e'),
        spaceAfter=12,
        spaceBefore=20,
    )
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=HexColor('#0f3460'),
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=8,
    )

    severity_colors = {
        'critical': HexColor('#dc2626'),
        'high': HexColor('#ea580c'),
        'medium': HexColor('#d97706'),
        'low': HexColor('#2563eb'),
        'info': HexColor('#6b7280'),
    }

    # ---- Title Page ----
    elements.append(Spacer(1, 60))
    elements.append(Paragraph('SafeWeb AI', title_style))
    elements.append(Paragraph('Security Scan Report', heading_style))
    elements.append(HRFlowable(width='100%', thickness=2, color=HexColor('#6366f1')))
    elements.append(Spacer(1, 20))

    # Scan info table
    scan_info = [
        ['Target', scan.target],
        ['Scan Type', scan.get_scan_type_display()],
        ['Status', scan.get_status_display()],
        ['Score', f'{scan.score}/100' if scan.score is not None else 'N/A'],
        ['Started', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
        ['Completed', scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
        ['Scan ID', str(scan.id)],
    ]
    info_table = Table(scan_info, colWidths=[100, 350])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#374151')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor('#e5e7eb')),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 30))

    # ---- Vulnerability Summary ----
    vulnerabilities = scan.vulnerabilities.all()
    summary = scan.vulnerability_summary

    elements.append(Paragraph('Vulnerability Summary', heading_style))

    summary_data = [
        ['Severity', 'Count'],
        ['Critical', str(summary.get('critical', 0))],
        ['High', str(summary.get('high', 0))],
        ['Medium', str(summary.get('medium', 0))],
        ['Low', str(summary.get('low', 0))],
        ['Info', str(summary.get('info', 0))],
        ['Total', str(summary.get('total', 0))],
    ]

    summary_table = Table(summary_data, colWidths=[120, 80])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 1), (0, 1), severity_colors['critical']),
        ('TEXTCOLOR', (0, 2), (0, 2), severity_colors['high']),
        ('TEXTCOLOR', (0, 3), (0, 3), severity_colors['medium']),
        ('TEXTCOLOR', (0, 4), (0, 4), severity_colors['low']),
        ('TEXTCOLOR', (0, 5), (0, 5), severity_colors['info']),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#d1d5db')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    elements.append(summary_table)
    elements.append(PageBreak())

    # ---- Detailed Findings ----
    elements.append(Paragraph('Detailed Findings', heading_style))
    elements.append(Spacer(1, 10))

    for i, vuln in enumerate(vulnerabilities, 1):
        sev_color = severity_colors.get(vuln.severity, HexColor('#6b7280'))

        elements.append(Paragraph(
            f'{i}. {vuln.name}',
            subheading_style,
        ))

        # Severity badge
        sev_style = ParagraphStyle(
            'SevBadge', parent=body_style,
            textColor=sev_color, fontName='Helvetica-Bold',
        )
        elements.append(Paragraph(
            f'Severity: {vuln.severity.upper()}'
            f' | CVSS: {vuln.cvss or "N/A"}'
            f' | CWE: {vuln.cwe or "N/A"}'
            f' | Category: {vuln.category}',
            sev_style,
        ))

        if vuln.affected_url:
            elements.append(Paragraph(
                f'<b>Affected URL:</b> {vuln.affected_url}', body_style
            ))

        elements.append(Paragraph(f'<b>Description:</b> {vuln.description}', body_style))
        elements.append(Paragraph(f'<b>Impact:</b> {vuln.impact}', body_style))
        elements.append(Paragraph(f'<b>Remediation:</b> {vuln.remediation}', body_style))

        if vuln.evidence:
            evidence_text = str(vuln.evidence).replace('\n', '<br/>').replace('<', '&lt;').replace('>', '&gt;').replace('&lt;br/&gt;', '<br/>')
            elements.append(Paragraph(f'<b>Evidence:</b><br/>{evidence_text}', body_style))

        elements.append(HRFlowable(width='100%', thickness=0.5, color=HexColor('#e5e7eb')))
        elements.append(Spacer(1, 10))

    # ---- Footer ----
    elements.append(Spacer(1, 30))

    # ---- Phase 16: Attack Chains section ----
    attack_graph_data = getattr(scan, 'recon_data', None) or {}
    if isinstance(attack_graph_data, dict):
        attack_graph_data = attack_graph_data.get('attack_graph', {})

    if attack_graph_data:
        elements.append(PageBreak())
        elements.append(Paragraph('Attack Chains', heading_style))
        elements.append(Spacer(1, 6))

        chains = attack_graph_data.get('chains', [])
        mermaid_src = attack_graph_data.get('mermaid', '')
        mitre_summary = attack_graph_data.get('mitre_summary', {})
        remediation_order = attack_graph_data.get('remediation_order', [])

        if chains:
            for chain in chains:
                chain_name = chain.get('chain_name', 'Unnamed Chain')
                chain_sev = chain.get('severity', 'medium')
                c_color = severity_colors.get(chain_sev, HexColor('#6b7280'))
                chain_style = ParagraphStyle(
                    'ChainHead', parent=body_style,
                    textColor=c_color, fontName='Helvetica-Bold',
                )
                elements.append(Paragraph(f'▸ {chain_name} ({chain_sev.upper()})', chain_style))
                desc = chain.get('description', '')
                if desc:
                    elements.append(Paragraph(desc, body_style))
                techniques = chain.get('mitre_techniques', [])
                if techniques:
                    elements.append(Paragraph(
                        f'MITRE Techniques: {", ".join(techniques)}', body_style
                    ))
                elements.append(Spacer(1, 4))
        else:
            elements.append(Paragraph('No complex attack chains detected.', body_style))

        if mermaid_src:
            elements.append(Paragraph('Attack Graph (Mermaid source)', subheading_style))
            merm_style = ParagraphStyle('Mermaid', parent=body_style, fontName='Courier',
                                        fontSize=7, leading=10)
            safe_mermaid = mermaid_src.replace('<', '&lt;').replace('>', '&gt;')
            elements.append(Paragraph(safe_mermaid.replace('\n', '<br/>'), merm_style))

        # MITRE ATT&CK Coverage table
        if mitre_summary:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph('MITRE ATT&CK Coverage', subheading_style))
            mitre_rows = [['Technique', 'Count']]
            for technique, count in sorted(mitre_summary.items()):
                mitre_rows.append([technique, str(count)])
            mitre_table = Table(mitre_rows, colWidths=[200, 80])
            mitre_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#d1d5db')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ]))
            elements.append(mitre_table)

        # Remediation Priority list
        if remediation_order:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph('Remediation Priority', subheading_style))
            rem_rows = [['Priority', 'Vulnerability', 'Severity', 'Chains Blocked']]
            for idx, item in enumerate(remediation_order, 1):
                rem_rows.append([
                    str(idx),
                    item.get('name', 'Unknown'),
                    item.get('severity', ''),
                    str(item.get('chain_count', 0)),
                ])
            rem_table = Table(rem_rows, colWidths=[50, 200, 80, 100])
            rem_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#d1d5db')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (3, -1), 'CENTER'),
            ]))
            elements.append(rem_table)

    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width='100%', thickness=1, color=HexColor('#6366f1')))
    footer_style = ParagraphStyle(
        'Footer', parent=body_style,
        fontSize=8, textColor=HexColor('#9ca3af'), alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f'Generated by SafeWeb AI on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        footer_style,
    ))
    elements.append(Paragraph(
        'This report is for authorized use only. Findings should be verified manually.',
        footer_style,
    ))

    doc.build(elements)
    return buffer.getvalue()


# ──────────────────────────────────────────────────────────────────────────
# Phase 17: HTML Report
# ──────────────────────────────────────────────────────────────────────────

def generate_html_report(scan, vulnerabilities=None) -> str:
    """
    Generate a full interactive HTML report.
    Works offline — all styles and scripts are inline.
    Sections:
      1. Executive Summary
      2. Scan Metadata
      3. Vulnerability Table (filterable)
      4. Attack Chains (Mermaid.js diagram)
      5. Per-Vulnerability Detail (collapsible)
      6. OWASP Coverage Matrix
      7. MITRE ATT&CK Heatmap
      8. Compliance Status
      9. Remediation Roadmap
    """
    from apps.scanning.engine.poc_generator import PoCGenerator
    from apps.scanning.engine.compliance import (
        get_owasp_coverage, get_pci_coverage,
    )

    if vulnerabilities is None:
        vulnerabilities = list(scan.vulnerabilities.all())

    poc_gen = PoCGenerator()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Pre-compute data
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulnerabilities:
        sev = (v.severity if hasattr(v, 'severity') else v.get('severity', 'info')).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    score = scan.score if hasattr(scan, 'score') else None
    target = scan.target if hasattr(scan, 'target') else ''
    scan_type = scan.get_scan_type_display() if hasattr(scan, 'get_scan_type_display') else ''
    started = scan.started_at.strftime('%Y-%m-%d %H:%M') if getattr(scan, 'started_at', None) else 'N/A'
    completed = scan.completed_at.strftime('%Y-%m-%d %H:%M') if getattr(scan, 'completed_at', None) else 'N/A'

    attack_graph_data = {}
    recon_data = getattr(scan, 'recon_data', None) or {}
    if isinstance(recon_data, dict):
        attack_graph_data = recon_data.get('attack_graph', {})

    chains = attack_graph_data.get('chains', [])
    mermaid_src = attack_graph_data.get('mermaid', '')
    mitre_summary = attack_graph_data.get('mitre_summary', {})
    remediation_order = attack_graph_data.get('remediation_order', [])

    owasp_coverage = get_owasp_coverage(vulnerabilities)
    pci_coverage = get_pci_coverage(vulnerabilities)

    # Grade
    grade = 'A' if (score or 0) >= 90 else \
            'B' if (score or 0) >= 75 else \
            'C' if (score or 0) >= 60 else \
            'D' if (score or 0) >= 40 else 'F'

    def esc(s):
        return html_module.escape(str(s or ''))

    def vuln_row(v, idx):
        sev = (v.severity if hasattr(v, 'severity') else v.get('severity', 'info')).lower()
        name = esc(v.name if hasattr(v, 'name') else v.get('name', ''))
        cat = esc(v.category if hasattr(v, 'category') else v.get('category', ''))
        url = esc(v.affected_url if hasattr(v, 'affected_url') else v.get('affected_url', ''))
        cvss = esc(v.cvss if hasattr(v, 'cvss') else v.get('cvss', ''))
        cwe = esc(v.cwe if hasattr(v, 'cwe') else v.get('cwe', ''))
        sev_class = {'critical': 'sev-critical', 'high': 'sev-high',
                     'medium': 'sev-medium', 'low': 'sev-low'}.get(sev, 'sev-info')
        return (
            f'<tr class="vuln-row" data-severity="{sev}" onclick="toggleDetail({idx})">'
            f'<td><span class="badge {sev_class}">{sev.upper()}</span></td>'
            f'<td>{name}</td><td>{cat}</td><td style="font-size:0.8em">{url}</td>'
            f'<td>{cvss}</td><td>{cwe}</td>'
            f'<td><button class="btn-detail">▼</button></td></tr>'
        )

    def vuln_detail(v, idx):
        (v.severity if hasattr(v, 'severity') else v.get('severity', 'info')).lower()
        name = esc(v.name if hasattr(v, 'name') else v.get('name', ''))
        desc = esc(v.description if hasattr(v, 'description') else v.get('description', ''))
        impact = esc(v.impact if hasattr(v, 'impact') else v.get('impact', ''))
        rem = esc(v.remediation if hasattr(v, 'remediation') else v.get('remediation', ''))
        evidence = esc(v.evidence if hasattr(v, 'evidence') else v.get('evidence', ''))

        vuln_dict = vars(v) if hasattr(v, '__dict__') else v
        poc = poc_gen.generate(vuln_dict)
        poc_cmd = esc(poc.get('curl_command', ''))
        poc_steps = ''.join(f'<li>{esc(s)}</li>' for s in poc.get('steps', []) if s)
        tool_cmds = ''
        for tool, cmd in poc.get('tool_commands', {}).items():
            tool_cmds += f'<p><b>{esc(tool)}:</b> <code>{esc(cmd)}</code></p>'

        return (
            f'<tr id="detail-{idx}" class="detail-row" style="display:none">'
            f'<td colspan="7"><div class="detail-box">'
            f'<h4>{name} — Detail</h4>'
            f'<p><b>Description:</b> {desc}</p>'
            f'<p><b>Impact:</b> {impact}</p>'
            f'<p><b>Remediation:</b> {rem}</p>'
            f'{"<p><b>Evidence:</b><pre>" + evidence[:500] + "</pre></p>" if evidence else ""}'
            f'<h5>Proof of Concept</h5>'
            f'<p><code>{poc_cmd}</code></p>'
            f'<ol>{poc_steps}</ol>'
            f'{tool_cmds}'
            f'</div></td></tr>'
        )

    vuln_rows_html = ''
    for i, v in enumerate(vulnerabilities):
        vuln_rows_html += vuln_row(v, i)
        vuln_rows_html += vuln_detail(v, i)

    # OWASP table rows
    owasp_rows = ''
    for cat_id, cat_name in [
        ('A01', 'A01:2021 Broken Access Control'),
        ('A02', 'A02:2021 Cryptographic Failures'),
        ('A03', 'A03:2021 Injection'),
        ('A04', 'A04:2021 Insecure Design'),
        ('A05', 'A05:2021 Security Misconfiguration'),
        ('A06', 'A06:2021 Vulnerable Components'),
        ('A07', 'A07:2021 Auth Failures'),
        ('A08', 'A08:2021 Software Integrity Failures'),
        ('A09', 'A09:2021 Logging Failures'),
        ('A10', 'A10:2021 SSRF'),
    ]:
        count = owasp_coverage.get(cat_id, 0)
        status = '✅' if count > 0 else '—'
        owasp_rows += f'<tr><td>{cat_name}</td><td>{status}</td><td>{count}</td></tr>'

    # MITRE heatmap rows
    mitre_rows = ''
    for technique, count in sorted(mitre_summary.items(), key=lambda x: -x[1]):
        mitre_rows += f'<tr><td>{esc(technique)}</td><td>{count}</td></tr>'

    # Remediation roadmap rows
    rem_rows = ''
    for idx, item in enumerate(remediation_order or [], 1):
        rem_rows += (
            f'<tr><td>{idx}</td>'
            f'<td>{esc(item.get("name", ""))}</td>'
            f'<td>{esc(item.get("severity", ""))}</td>'
            f'<td>{item.get("chain_count", 0)}</td></tr>'
        )

    # Chains section
    chains_html = ''
    if chains:
        for ch in chains:
            cn = esc(ch.get('chain_name', ''))
            cs = ch.get('severity', 'medium')
            cd = esc(ch.get('description', ''))
            ct = esc(', '.join(ch.get('mitre_techniques', [])))
            chains_html += (
                f'<div class="chain-card sev-{cs.lower()}-border">'
                f'<b>{cn}</b> <span class="badge sev-{cs.lower()}">{cs.upper()}</span>'
                f'<p>{cd}</p>'
                f'{"<p><small>MITRE: " + ct + "</small></p>" if ct else ""}'
                f'</div>'
            )
    else:
        chains_html = '<p>No complex attack chains detected.</p>'

    mermaid_section = ''
    if mermaid_src:
        mermaid_section = (
            '<div class="section"><h2>Attack Graph Diagram</h2>'
            f'<div class="mermaid">{esc(mermaid_src)}</div></div>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeWeb AI — Security Report</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f8f9fa;color:#222;margin:0;padding:0}}
  .container{{max-width:1200px;margin:0 auto;padding:24px}}
  h1{{color:#1a1a2e;font-size:2em}}
  h2{{color:#16213e;border-bottom:2px solid #6366f1;padding-bottom:4px}}
  h4{{margin-bottom:4px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;color:#fff}}
  .sev-critical{{background:#dc2626}}.sev-high{{background:#ea580c}}
  .sev-medium{{background:#d97706}}.sev-low{{background:#2563eb}}.sev-info{{background:#6b7280}}
  .sev-critical-border{{border-left:4px solid #dc2626}}.sev-high-border{{border-left:4px solid #ea580c}}
  .sev-medium-border{{border-left:4px solid #d97706}}.sev-low-border{{border-left:4px solid #2563eb}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:16px;margin:16px 0}}
  .summary-card{{background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  .summary-card .num{{font-size:2em;font-weight:bold}}
  .section{{background:#fff;border-radius:8px;padding:20px;margin:16px 0;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  table{{width:100%;border-collapse:collapse;font-size:0.9em}}
  th{{background:#f3f4f6;text-align:left;padding:8px;border-bottom:2px solid #d1d5db}}
  td{{padding:8px;border-bottom:1px solid #e5e7eb;vertical-align:top}}
  .vuln-row{{cursor:pointer}}.vuln-row:hover{{background:#f9fafb}}
  .detail-row td{{background:#f0f4ff}}
  .detail-box{{padding:12px}}
  pre{{background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;overflow-x:auto;font-size:0.85em}}
  code{{background:#f3f4f6;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:0.9em}}
  .btn-detail{{background:none;border:none;cursor:pointer;color:#6366f1;font-size:1em}}
  .chain-card{{background:#fff;border-radius:6px;padding:12px;margin:8px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
  select,input{{padding:6px 10px;border:1px solid #d1d5db;border-radius:4px;margin-right:8px}}
  .filter-bar{{margin-bottom:12px}}
  .grade{{font-size:3em;font-weight:bold;color:#6366f1}}
  footer{{text-align:center;color:#9ca3af;font-size:0.8em;margin-top:32px}}
</style>
</head>
<body>
<div class="container">
  <h1>SafeWeb AI Security Report</h1>
  <p>Generated: {now_str}</p>

  <!-- Executive Summary -->
  <div class="section">
    <h2>1. Executive Summary</h2>
    <div style="display:flex;gap:24px;align-items:center">
      <div><span class="grade">{grade}</span><br><small>Security Grade</small></div>
      <div><span class="grade" style="font-size:2em">{score if score is not None else "N/A"}</span><br><small>Score / 100</small></div>
    </div>
    <div class="summary-grid">
      <div class="summary-card"><div class="num" style="color:#dc2626">{severity_counts['critical']}</div><div>Critical</div></div>
      <div class="summary-card"><div class="num" style="color:#ea580c">{severity_counts['high']}</div><div>High</div></div>
      <div class="summary-card"><div class="num" style="color:#d97706">{severity_counts['medium']}</div><div>Medium</div></div>
      <div class="summary-card"><div class="num" style="color:#2563eb">{severity_counts['low']}</div><div>Low</div></div>
      <div class="summary-card"><div class="num" style="color:#6b7280">{severity_counts['info']}</div><div>Info</div></div>
      <div class="summary-card"><div class="num">{len(vulnerabilities)}</div><div>Total</div></div>
    </div>
  </div>

  <!-- Scan Metadata -->
  <div class="section">
    <h2>2. Scan Metadata</h2>
    <table style="max-width:600px">
      <tr><th>Target</th><td>{esc(target)}</td></tr>
      <tr><th>Scan Type</th><td>{esc(scan_type)}</td></tr>
      <tr><th>Started</th><td>{started}</td></tr>
      <tr><th>Completed</th><td>{completed}</td></tr>
    </table>
  </div>

  <!-- Vulnerability Table -->
  <div class="section">
    <h2>3. Vulnerabilities</h2>
    <div class="filter-bar">
      <select id="sev-filter" onchange="filterVulns()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
    </div>
    <table id="vuln-table">
      <thead><tr><th>Severity</th><th>Name</th><th>Category</th><th>URL</th><th>CVSS</th><th>CWE</th><th></th></tr></thead>
      <tbody>{vuln_rows_html}</tbody>
    </table>
  </div>

  <!-- Attack Chains -->
  <div class="section">
    <h2>4. Attack Chains</h2>
    {chains_html}
  </div>

  {mermaid_section}

  <!-- OWASP Coverage -->
  <div class="section">
    <h2>6. OWASP Top 10 Coverage</h2>
    <table style="max-width:600px">
      <thead><tr><th>Category</th><th>Affected</th><th>Finding Count</th></tr></thead>
      <tbody>{owasp_rows}</tbody>
    </table>
  </div>

  <!-- MITRE Heatmap -->
  <div class="section">
    <h2>7. MITRE ATT&amp;CK Coverage</h2>
    {"<table style='max-width:400px'><thead><tr><th>Technique</th><th>Count</th></tr></thead><tbody>" + mitre_rows + "</tbody></table>" if mitre_rows else "<p>No MITRE mappings found.</p>"}
  </div>

  <!-- Compliance -->
  <div class="section">
    <h2>8. Compliance Status</h2>
    <h4>PCI DSS v4</h4>
    <table style="max-width:600px">
      <thead><tr><th>Requirement</th><th>Affected</th><th>Count</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td>{esc(req)}</td><td>{'⚠️' if cnt>0 else '✅'}</td><td>{cnt}</td></tr>" for req, cnt in pci_coverage.items())}
      </tbody>
    </table>
  </div>

  <!-- Remediation Roadmap -->
  <div class="section">
    <h2>9. Remediation Roadmap</h2>
    {"<table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Chains Blocked</th></tr></thead><tbody>" + rem_rows + "</tbody></table>" if rem_rows else "<p>No remediation data available.</p>"}
  </div>

  <footer>
    <p>Generated by SafeWeb AI &mdash; {now_str}<br>
    This report is for authorised security assessment purposes only.</p>
  </footer>
</div>

<script>
mermaid.initialize({{startOnLoad:true, theme:'default'}});

function toggleDetail(idx) {{
  var row = document.getElementById('detail-' + idx);
  if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}}

function filterVulns() {{
  var val = document.getElementById('sev-filter').value;
  document.querySelectorAll('.vuln-row').forEach(function(row) {{
    row.style.display = (!val || row.getAttribute('data-severity') === val) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""
    return html


# ──────────────────────────────────────────────────────────────────────────
# Phase 17: SARIF Report
# ──────────────────────────────────────────────────────────────────────────

def generate_sarif_report(scan, vulnerabilities=None) -> dict:
    """
    Generate a SARIF 2.1.0 report.
    Compatible with GitHub Code Scanning, VS Code SARIF viewer, Azure DevOps.
    """
    if vulnerabilities is None:
        vulnerabilities = list(scan.vulnerabilities.all())

    rules = {}
    results = []

    for v in vulnerabilities:
        name = v.name if hasattr(v, 'name') else v.get('name', 'UnknownVuln')
        rule_id = name.replace(' ', '_').replace('/', '_')
        sev = (v.severity if hasattr(v, 'severity') else v.get('severity', 'info')).lower()
        description = v.description if hasattr(v, 'description') else v.get('description', '')
        remediation = v.remediation if hasattr(v, 'remediation') else v.get('remediation', '')
        url = v.affected_url if hasattr(v, 'affected_url') else v.get('affected_url', '')
        cwe = v.cwe if hasattr(v, 'cwe') else v.get('cwe', '')

        sarif_level = {
            'critical': 'error', 'high': 'error',
            'medium': 'warning', 'low': 'note', 'info': 'none',
        }.get(sev, 'warning')

        # Build rules dict (deduplicated)
        if rule_id not in rules:
            rule_entry = {
                'id': rule_id,
                'name': name,
                'shortDescription': {'text': name},
                'fullDescription': {'text': description},
                'helpUri': f'https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html' if cwe else '',
                'properties': {
                    'security-severity': {
                        'critical': '9.5', 'high': '8.0',
                        'medium': '5.5', 'low': '3.0', 'info': '1.0',
                    }.get(sev, '5.0'),
                    'tags': ['security'],
                },
                'defaultConfiguration': {'level': sarif_level},
            }
            if remediation:
                rule_entry['help'] = {'text': remediation, 'markdown': remediation}
            rules[rule_id] = rule_entry

        result_entry = {
            'ruleId': rule_id,
            'level': sarif_level,
            'message': {'text': description},
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': url or scan.target,
                            'uriBaseId': '%SRCROOT%',
                        },
                    },
                }
            ],
            'properties': {'severity': sev},
        }

        evidence = v.evidence if hasattr(v, 'evidence') else v.get('evidence', '')
        if evidence:
            result_entry['message']['text'] += f'\n\nEvidence: {str(evidence)[:500]}'

        results.append(result_entry)

    sarif = {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'SafeWeb AI Scanner',
                        'version': '2.0.0',
                        'informationUri': 'https://safeweb.ai',
                        'rules': list(rules.values()),
                    }
                },
                'results': results,
                'invocations': [
                    {
                        'executionSuccessful': True,
                        'startTimeUtc': scan.started_at.isoformat() if getattr(scan, 'started_at', None) else '',
                        'endTimeUtc': scan.completed_at.isoformat() if getattr(scan, 'completed_at', None) else '',
                    }
                ],
                'properties': {
                    'target': scan.target if hasattr(scan, 'target') else '',
                    'score': scan.score if hasattr(scan, 'score') else None,
                },
            }
        ],
    }
    return sarif

