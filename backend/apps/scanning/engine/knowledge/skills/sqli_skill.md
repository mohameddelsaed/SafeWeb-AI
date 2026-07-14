---
name: SQL Injection Exploitation Skill
tags: [sqli, sql_injection, database]
---
# SQL Injection Verification Protocol

1. Test for boolean-based blind injection using standard tautologies (`' OR 1=1--`).
2. Test for time-based blind injection (`' OR SLEEP(5)--`).
3. If confirmed, use `sqlmap` via sandbox wrapper with safe flags (`--batch --level=1 --risk=1`).
4. Extract current database user and version as proof capsule. Do not dump user tables.
