---
Source agent: Frontend Analysis Agent
Run date: 2026-06-23
Inputs used: src/App.tsx, src/main.tsx
Status: draft
---

# Component Hierarchy

- **`main.tsx`** (Root mount point)
  - **`App`** (`App.tsx`)
    - **`Router`** (`react-router-dom` BrowserRouter)
      - **`AuthProvider`** (Context provider for auth state)
        - **`Routes`**
          - **`<L>` Wrapper** (Custom component handling `AppErrorBoundary` and `Suspense`)
            - **Public Pages**: `Home`, `Login`, `Register`, `Learn`, `Docs`, `About`, etc.
            - **Protected Pages** (Wrapped in `ProtectedRoute`): `Dashboard`, `ScanWebsite`, `ScanResults`, `Profile`, etc.
            - **Admin Pages** (Wrapped in `ProtectedRoute` with `adminOnly`): `AdminDashboard`, `AdminUsers`, `AdminScans`, etc.
        - **`ChatbotWidget`** (Lazily loaded outside of routes to persist across navigation)
