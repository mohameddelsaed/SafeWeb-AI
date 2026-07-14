# Multi-Tenancy Patterns Research

## Overview
SafeWeb AI requires a robust multi-tenancy strategy to isolate user data, scans, and vulnerabilities.

## Recommended Pattern: Shared Database, Shared Schema
Given the Django backend, the most practical approach is logical separation.
- Every tenant (User/Organization) shares the same database and schema.
- Tenant isolation is enforced at the application layer via ORM filtering (e.g., `Scan.objects.filter(user=request.user)`).

## Alternatives Considered
- **Database per Tenant**: Too high overhead for the current scale.
- **Schema per Tenant**: Supported by PostgreSQL but complex to manage with Django migrations.

## Conclusion
Proceed with Shared Database, Shared Schema, enforcing isolation via application-level query constraints.
