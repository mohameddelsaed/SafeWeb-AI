export const VULNERABILITY_CATEGORIES = [
    'SQL Injection',
    'Cross-Site Scripting (XSS)',
    'Cross-Site Request Forgery (CSRF)',
    'Broken Authentication',
    'Security Misconfiguration',
    'Sensitive Data Exposure',
    'Broken Access Control',
    'XML External Entities (XXE)',
    'Insecure Deserialization',
    'Using Components with Known Vulnerabilities',
    'Insufficient Logging & Monitoring',
    'Server-Side Request Forgery (SSRF)',
];

export const SCAN_DEPTHS = [
    { value: 'shallow', label: 'Shallow (Fast)', description: 'Quick scan of main pages' },
    { value: 'medium', label: 'Medium (Recommended)', description: 'Balanced scan depth' },
    { value: 'deep', label: 'Deep (Thorough)', description: 'Comprehensive deep scan' },
];

export const SEVERITY_COLORS = {
    critical: {
        text: 'text-status-critical',
        bg: 'bg-status-critical/10',
        border: 'border-status-critical',
    },
    high: {
        text: 'text-status-high',
        bg: 'bg-status-high/10',
        border: 'border-status-high',
    },
    medium: {
        text: 'text-status-medium',
        bg: 'bg-status-medium/10',
        border: 'border-status-medium',
    },
    low: {
        text: 'text-status-low',
        bg: 'bg-status-low/10',
        border: 'border-status-low',
    },
};

export const API_ENDPOINTS = {
    auth: {
        login: '/api/auth/login',
        register: '/api/auth/register',
        logout: '/api/auth/logout',
        verify: '/api/auth/verify',
    },
    scan: {
        website: '/api/scan/website',
        file: '/api/scan/file',
        url: '/api/scan/url',
        status: '/api/scan/status',
    },
    results: {
        list: '/api/results',
        detail: '/api/results/:id',
        export: '/api/results/:id/export',
    },
    user: {
        profile: '/api/user/profile',
        settings: '/api/user/settings',
    },
};
