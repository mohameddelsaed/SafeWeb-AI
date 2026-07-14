# Learning Center 500-Article Execution Plan (Beginner -> Expert)

## Objective
Build a 500-article, production-grade web application security and secure coding learning center for both developers and specialists.

## Source Policy (Required)
- Rewritten synthesis only (no verbatim copying from sources).
- Every article must cite 3-6 references and include OWASP/CWE/WSTG/ASVS mappings where applicable.
- Primary source families:
  - PortSwigger Web Security Academy + Research
  - OWASP Top 10, ASVS, WSTG, Cheat Sheet Series, API Security Top 10
  - HackerOne public Hacktivity/public disclosures (manually curated summaries)
  - DEF CON talks/media and whitepapers (manually curated summaries)
  - MITRE CWE/CAPEC and relevant RFC/NIST docs

## Difficulty Distribution (500 Total)
- Foundation (beginner): 180
- Practitioner (intermediate): 170
- Specialist (advanced/expert): 150

## Category Distribution Targets
- injection: 70
- xss: 60
- api_security: 80
- authentication: 70
- access_control: 60
- security_headers: 45
- cryptography: 45
- network_security: 40
- best_practices: 30

## Batch Strategy
- 10 outline batches x 50 articles each.
- Validate each batch with `validate_articles --strict --min-score 75` before bulk loading.
- Publish in controlled waves after editorial QA and technical QA.

## Quality Gates
- No placeholders in final published content.
- Mandatory sections: threat model, attack mechanics, detection, secure implementation, checklist, references.
- Slug uniqueness and taxonomy consistency required.
- Security code examples required for secure coding themed articles.
