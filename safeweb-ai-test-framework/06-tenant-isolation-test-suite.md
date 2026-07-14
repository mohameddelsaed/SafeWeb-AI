# 06 - Multi-Tenant Isolation Test Suite

## Objective
Prove mathematically that data leakage between organizations is impossible.

## Scope
- `OrganizationMiddleware` Context Isolation
- Cross-tenant IDOR

## Specifications & Assertions
1. **Data Segregation**:
   - Setup: Create `Org A` and `Org B`. Create `Scan A` in `Org A`.
   - Action: User from `Org B` requests `GET /api/v1/scan/{scan_a_id}/` passing `X-Organization-ID: Org_B_ID`.
   - Assert: HTTP 404 Not Found (not 403, to prevent ID enumeration).
2. **Middleware Tampering**:
   - Action: User from `Org B` passes `X-Organization-ID: Org_A_ID` in headers.
   - Assert: Middleware detects user is not a member of `Org A` and sets `request.organization = None` or denies access.

## AI Prompt Instructions
"Create `test_tenant_isolation.py`. You must instantiate multiple organizations, multiple users, and aggressively attempt to read, edit, and delete cross-tenant data."\n