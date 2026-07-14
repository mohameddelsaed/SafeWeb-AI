---
Source agent: Security Review Agent
Run date: 2026-06-23
Inputs used: src/services/api.ts, backend/config/settings/base.py, backend/apps/accounts/models.py, backend/apps/scanning/views.py
Status: draft
---

# Authentication and Session Review

- **Mechanism**: JSON Web Tokens (JWT) via `rest_framework_simplejwt`.
- **Client Storage**: Tokens are stored in the client's `localStorage` (`access_token` and `refresh_token`), as seen in `src/services/api.ts`.
- **Session Tracking**: The `UserSession` model logs IPs and User Agents but does not replace JWT statelessness.
- **2FA**: Supported natively on the `User` model (`is_2fa_enabled`, `two_fa_secret`).
- **Passwords**: Managed through standard Django validators defined in `AUTH_PASSWORD_VALIDATORS`.
