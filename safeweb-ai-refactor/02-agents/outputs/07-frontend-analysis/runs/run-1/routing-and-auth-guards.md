---
Source agent: Frontend Analysis Agent
Run date: 2026-06-23
Inputs used: src/App.tsx, src/components/ProtectedRoute.tsx
Status: draft
---

# Routing and Auth Guards

- **Router**: `react-router-dom` (`BrowserRouter`).
- **Code Splitting**: All page components are lazily loaded using `React.lazy()` to reduce the initial bundle size, chunked specifically to isolate admin pages.
- **Auth Guard Mechanism**: The `ProtectedRoute` component is used to wrap restricted routes.
  - It consumes `useAuth` from the `AuthContext`.
  - Displays a loading spinner while `isLoading` is true.
  - Returns `<Navigate to="/login" replace />` if `isAuthenticated` is false.
- **Role-Based Access Control (RBAC)**: `ProtectedRoute` supports an `adminOnly` prop. If the `user.role` is not `'admin'`, it returns `<Navigate to="/dashboard" replace />`.
