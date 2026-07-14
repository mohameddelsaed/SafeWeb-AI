# 01 - Unit Test Suite Specification

## Objective
Validate the atomic business logic of SafeWeb AI isolated from the database and external networks.

## Scope
1. **Accounts App**: JWT token generation, password validators, role normalizations.
2. **Scanning App**: URL scope validation (e.g., rejecting `localhost`), severity calculations, CVSS scoring logic.
3. **AI Reasoning Engine**: System prompt generation, JSON parsing from LLM outputs.

## Specifications & Assertions

### Accounts Unit Tests
- `test_password_validator`: Assert that passwords without symbols, numbers, and uppercase letters raise `ValidationError`.
- `test_user_role_assignment`: Assert that a user defaults to `user` role unless `is_superuser` is passed.

### Scanning Unit Tests
- `test_scope_validator_rejects_private_ips`: Assert that `validate_domain` blocks `169.254.169.254` and `127.0.0.1`.
- `test_severity_calculation`: Assert that a CVSS score of 9.5 maps to `CRITICAL` severity enum.

### AI Engine Unit Tests
- `test_llm_json_extractor`: Pass dirty markdown strings (e.g., ````json { ... } ````) to the extractor and assert clean dict return.

## AI Prompt Instructions
"Generate `pytest` unit tests for `backend/apps/scanning` and `backend/apps/accounts`. Use `unittest.mock` for any external dependencies. Ensure 90% line coverage for utility functions."\n