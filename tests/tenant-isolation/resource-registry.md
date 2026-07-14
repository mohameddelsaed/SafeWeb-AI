# SafeWeb AI — Tenant Isolation Resource Registry

This registry maps every database table and model in the multi-tenant SaaS architecture to its corresponding API endpoints and the enforcement mechanism guaranteeing strict organization segregation.

| Database Table / Django Model | Primary API Endpoint | Tenant Scoping Column | Isolation Enforcement Mechanism | Verification Test Cited |
| :--- | :--- | :---: | :--- | :--- |
| `accounts_organization` | `GET /api/v1/organizations/` | `id` | `request.user.organizations` filter | `test_tenant_isolation.py:L11-32` |
| `accounts_organizationmembership` | `GET /api/v1/members/` | `organization_id` | `OrganizationMembership` RBAC check | `test_tenant_isolation.py:L27-31` |
| `scanning_scan` | `GET /api/v1/scan/{id}/` | `organization_id` | DRF `get_queryset()` tenant filtering + `X-Organization-ID` header validation | `test_tenant_isolation.py:L72-82` |
| `scanning_target` | `DELETE /api/v1/scan/targets/{id}/` | `organization_id` | Object-level permission boundary (`IsOrgMember`) | `test_tenant_isolation.py:L112-118` |
| `scanning_vulnerability` | `GET /api/v1/scan/{id}/findings/` | `scan__organization_id` | Nested queryset join scoped to authenticated tenant | `test_models.py` |
| `scanning_scheduledscan` | `GET /api/v1/schedules/` | `organization_id` | Celery task tenant context injection | `test_api_endpoints.py` |
| `scanning_webhook` | `POST /api/v1/webhooks/` | `organization_id` | HMAC signature payload tenant verification | `test_webhooks.py` |
| `scanning_discoveredasset` | `GET /api/v1/assets/` | `organization_id` | `DiscoveredAsset` tenant scope isolation | `test_multi_target_api.py` |

### Security Boundary Guarantees
1. **No Cross-Tenant Query Contamination**: All API viewsets inherit from `TenantScopedViewSet`, automatically injecting `.filter(organization_id=request.org_id)`.
2. **Header Tampering Prevention**: The `TenantIsolationMiddleware` intercepts requests and verifies that `request.user` has an active `OrganizationMembership` for the UUID supplied in `X-Organization-ID`. If unverified, HTTP 403 Forbidden / 404 Not Found is returned immediately.
