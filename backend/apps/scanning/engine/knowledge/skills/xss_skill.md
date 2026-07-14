---
name: Cross-Site Scripting Exploitation Skill
tags: [xss, reflected_xss, stored_xss]
---
# XSS Verification Protocol

1. Test parameter reflection with unique alphanumeric canary string (`safeweb_canary_2026`).
2. If canary reflects unescaped, test basic context breakers (`<script>alert(1)</script>`, `"><svg onload=alert(1)>`).
3. Capture DOM response proof capsule showing unescaped payload reflection.
