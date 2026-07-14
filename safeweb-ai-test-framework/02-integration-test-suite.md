# 02 - Integration Test Suite Specification

## Objective
Validate the interaction between Django Views, Serializers, Models, and the Postgres Database.

## Scope
- Authentication Endpoints (Login, Register, 2FA)
- Organization Management (Memberships)
- Scan CRUD Operations
- Target Management

## Specifications & Assertions

### Auth Integration
- **Register Flow**: Post to `/api/v1/auth/register/`. Assert 201 Created. Assert `User` exists in DB. Assert JWT token returned.
- **Login Flow**: Post to `/api/v1/auth/login/`. Assert 200 OK. Assert Last Login IP is updated.

### Scan Integration
- **Create Scan**: Post to `/api/v1/scan/website/`. 
  - Assert HTTP 201.
  - Assert `Scan` object is saved to DB with state `pending`.
  - Assert `execute_scan_task.delay()` was called (mock celery).

## AI Prompt Instructions
"Implement Django REST Framework `APITestCase` classes for the integration suite. Use `pytest.mark.django_db`. Create a `conftest.py` with reusable fixtures for authenticated users, JWT tokens, and organizations."\n