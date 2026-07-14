import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

// ── Axios instance ──────────────────────────────────────────────────
const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api/v1` : '/api/v1',
    headers: { 'Content-Type': 'application/json' },
});

// ── Token helpers ───────────────────────────────────────────────────
export const getAccessToken = () => localStorage.getItem('access_token');
export const getRefreshToken = () => localStorage.getItem('refresh_token');
export const setTokens = (access: string, refresh: string) => {
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
};
export const clearTokens = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
};

// ── Request interceptor – attach JWT ────────────────────────────────
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const token = getAccessToken();
    if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// ── Response interceptor – auto-refresh on 401 ─────────────────────
let isRefreshing = false;
let failedQueue: { resolve: (v: unknown) => void; reject: (e: unknown) => void }[] = [];

const processQueue = (error: unknown) => {
    failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(undefined)));
    failedQueue = [];
};

api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        if (error.response?.status === 401 && !originalRequest._retry) {
            const refresh = getRefreshToken();
            if (!refresh) {
                clearTokens();
                window.location.href = '/login';
                return Promise.reject(error);
            }

            if (isRefreshing) {
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then(() => api(originalRequest));
            }

            originalRequest._retry = true;
            isRefreshing = true;

            try {
                const baseUrl = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api/v1` : '/api/v1';
                const { data } = await axios.post(`${baseUrl}/auth/refresh/`, { refresh });
                setTokens(data.access, data.refresh || refresh);
                processQueue(null);
                return api(originalRequest);
            } catch (refreshError) {
                processQueue(refreshError);
                clearTokens();
                window.location.href = '/login';
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }

        return Promise.reject(error);
    },
);

// ── Auth endpoints ──────────────────────────────────────────────────
export const authAPI = {
    register: (data: { name: string; email: string; password: string; confirmPassword: string }) =>
        api.post('/auth/register/', data),

    login: (data: { email: string; password: string; rememberMe?: boolean }) =>
        api.post('/auth/login/', data),

    logout: (refresh: string) =>
        api.post('/auth/logout/', { refresh }),

    verify: () => api.get('/auth/verify/'),

    refresh: (refresh: string) =>
        api.post('/auth/refresh/', { refresh }),

    forgotPassword: (email: string) =>
        api.post('/auth/forgot-password/', { email }),

    resetPassword: (data: { token: string; password: string }) =>
        api.post('/auth/reset-password/', data),

    googleAuth: (token: string) =>
        api.post('/auth/google/', { token }),
};

// ── User / Profile endpoints ────────────────────────────────────────
export const userAPI = {
    getProfile: () => api.get('/user/profile/'),

    updateProfile: (data: Record<string, unknown>) =>
        api.patch('/user/profile/', data),

    changePassword: (data: { currentPassword: string; newPassword: string; confirmPassword: string }) =>
        api.post('/auth/change-password/', data),

    getAPIKeys: () => api.get('/user/profile/api-keys/'),

    createAPIKey: (name: string) =>
        api.post('/user/profile/api-keys/', { name }),

    deleteAPIKey: (id: string) =>
        api.delete(`/user/profile/api-keys/${id}/`),

    getSessions: () => api.get('/user/profile/sessions/'),

    enable2FA: () => api.post('/user/profile/2fa/enable/'),

    verify2FA: (token: string) =>
        api.post('/user/profile/2fa/verify/', { token }),
};

// ── Scan endpoints ──────────────────────────────────────────────────
export const scanAPI = {
    createScan: (data: {
        target: string;
        scope_type: string;
        seed_domains?: string[];
        scanDepth: string;
        checkSsl: boolean;
        followRedirects: boolean;
        controlExternalTools: boolean;
        scanMode?: string;
        wafEvasion?: boolean;
        authConfig?: Record<string, string>;
    }) => api.post('/scan/website/', data),

    resolveScope: (id: string) =>
        api.post(`/scan/${id}/resolve/`),

    confirmScope: (id: string, selectedDomains: string[]) =>
        api.post(`/scan/${id}/confirm/`, { selectedDomains }),

    // Legacy alias
    scanWebsite: (data: Record<string, unknown>) => api.post('/scan/website/', data),

    // DEACTIVATED: File/URL threat detection endpoints removed
    // scanFile: (formData: FormData) =>
    //     api.post('/scan/file/', formData, {
    //         headers: { 'Content-Type': 'multipart/form-data' },
    //     }),
    // scanUrl: (url: string) =>
    //     api.post('/scan/url/', { url }),

    getResults: (id: string) =>
        api.get(`/scan/${id}/`),

    getList: (params?: Record<string, string>) =>
        api.get('/scans/', { params }),

    deleteScan: (id: string) =>
        api.delete(`/scan/${id}/delete/`),

    rescan: (id: string) =>
        api.post(`/scan/${id}/rescan/`),

    exportScan: (id: string, format: string) =>
        api.get(`/scan/${id}/export/`, {
            params: { export_format: format },
            responseType: format === 'json' ? 'json' : 'blob',
        }),

    // ── Findings (paginated, filtered) ─────────────────────────────
    getFindings: (id: string, params?: { severity?: string; category?: string; search?: string; page?: number }) =>
        api.get(`/scan/${id}/findings/`, { params }),

    markFalsePositive: (scanId: string, vulnId: string, isFalsePositive: boolean) =>
        api.patch(`/scan/${scanId}/findings/${vulnId}/`, { is_false_positive: isFalsePositive }),

    rescanFinding: (scanId: string, vulnId: string) =>
        api.post(`/scan/${scanId}/rescan-finding/`, { finding_id: vulnId }),

    // ── Scan comparison ─────────────────────────────────────────────
    compareScan: (id1: string, id2: string) =>
        api.get(`/scan/compare/${id1}/${id2}/`),

    // ── SSE stream URL (not an axios call — returns the URL string) ─
    getStreamUrl: (id: string) => {
        const token = getAccessToken();
        const base = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : '/api';
        return `${base}/scan/${id}/stream/?token=${token}`;
    },

    // ── Scan profiles ───────────────────────────────────────────────
    getScanProfiles: () => api.get('/scan/profiles/'),

    // ── Auth config ─────────────────────────────────────────────────
    createAuthConfig: (data: Record<string, unknown>) =>
        api.post('/scan/auth-configs/', data),

    updateAuthConfig: (id: string, data: Record<string, unknown>) =>
        api.patch(`/scan/auth-configs/${id}/`, data),

    deleteAuthConfig: (id: string) =>
        api.delete(`/scan/auth-configs/${id}/`),
};

// ── Webhooks ────────────────────────────────────────────────────────
export const webhookAPI = {
    getAll: () => api.get('/scan/webhooks/'),

    create: (data: { url: string; secret?: string; events: string[]; isActive?: boolean; maxRetries?: number }) =>
        api.post('/scan/webhooks/', data),

    update: (id: string, data: Record<string, unknown>) =>
        api.patch(`/scan/webhooks/${id}/`, data),

    delete: (id: string) =>
        api.delete(`/scan/webhooks/${id}/`),

    test: (id: string) =>
        api.post(`/scan/webhooks/${id}/test/`),

    getDeliveries: (id: string) =>
        api.get(`/scan/webhooks/${id}/deliveries/`),
};

// ── Scopes ──────────────────────────────────────────────────────────
export const scopeAPI = {
    getAll: () => api.get('/scan/scopes/'),

    create: (data: { name: string; description?: string; organization?: string; inScope: string[]; outOfScope?: string[] }) =>
        api.post('/scan/scopes/', data),

    update: (id: string, data: Record<string, unknown>) =>
        api.patch(`/scan/scopes/${id}/`, data),

    delete: (id: string) =>
        api.delete(`/scan/scopes/${id}/`),

    import: (data: { format: string; content: string }) =>
        api.post('/scan/scopes/import/', data),

    validate: (id: string, url: string) =>
        api.post(`/scan/scopes/${id}/validate/`, { url }),
};

// ── Multi-target scans ───────────────────────────────────────────────
export const multiTargetAPI = {
    getAll: () => api.get('/scan/multi/'),

    create: (data: {
        name: string;
        targets: string[];
        scopeId?: string;
        scanDepth?: string;
        parallelLimit?: number;
    }) => api.post('/scan/multi/create/', data),

    get: (id: string) => api.get(`/scan/multi/${id}/`),

    delete: (id: string) => api.delete(`/scan/multi/${id}/`),
};

// ── Scheduled scans ─────────────────────────────────────────────────
export const scheduledScanAPI = {
    getAll: () => api.get('/scan/scheduled/'),

    create: (data: {
        name: string;
        target: string;
        scanConfig?: Record<string, unknown>;
        schedulePreset?: string;
        cronExpr?: string;
        notifications?: Record<string, boolean>;
    }) => api.post('/scan/scheduled/', data),

    update: (id: string, data: Record<string, unknown>) =>
        api.patch(`/scan/scheduled/${id}/`, data),

    delete: (id: string) =>
        api.delete(`/scan/scheduled/${id}/`),

    toggle: (id: string, isActive: boolean) =>
        api.patch(`/scan/scheduled/${id}/`, { is_active: isActive }),
};

// ── Asset inventory ──────────────────────────────────────────────────
export const assetAPI = {
    getAll: (params?: { assetType?: string; isNew?: boolean; isActive?: boolean; search?: string }) =>
        api.get('/scan/assets/', { params }),

    get: (id: string) => api.get(`/scan/assets/${id}/`),

    update: (id: string, data: Record<string, unknown>) =>
        api.patch(`/scan/assets/${id}/`, data),

    delete: (id: string) => api.delete(`/scan/assets/${id}/`),

    getMonitorRecords: (params?: { acknowledged?: boolean }) =>
        api.get('/scan/asset-monitor/', { params }),

    acknowledgeRecord: (id: string) =>
        api.post(`/scan/asset-monitor/${id}/acknowledge/`),
};

// ── Nuclei templates ─────────────────────────────────────────────────
export const nucleiAPI = {
    getAll: () => api.get('/scan/nuclei-templates/'),

    create: (data: { name: string; description?: string; category?: string; severity?: string }) =>
        api.post('/scan/nuclei-templates/upload/', data),

    toggle: (id: string, isActive: boolean) =>
        api.patch(`/scan/nuclei-templates/${id}/`, { is_active: isActive }),

    delete: (id: string) => api.delete(`/scan/nuclei-templates/${id}/`),
};

// ── Dashboard ───────────────────────────────────────────────────────
export const dashboardAPI = {
    get: () => api.get('/dashboard/'),

    getTrends: (days = 30) => api.get('/dashboard/trends/', { params: { days } }),
};

// ── Chat endpoints ──────────────────────────────────────────────────
export const chatAPI = {
    send: (data: { message: string; sessionId?: string; scanId?: string }) =>
        api.post('/chat/', data),

    getSessions: () => api.get('/chat/sessions/'),

    getSession: (id: string) =>
        api.get(`/chat/sessions/${id}/`),

    deleteSession: (id: string) =>
        api.delete(`/chat/sessions/${id}/`),

    sendFeedback: (messageId: string, feedback: 'positive' | 'negative') =>
        api.post(`/chat/messages/${messageId}/feedback/`, { feedback }),

    getSuggestions: (scanId?: string) =>
        api.get('/chat/suggestions/', { params: scanId ? { scan_id: scanId } : {} }),
    getAnalytics: (timeRange = '30d') =>
        api.get('/chat/analytics/', { params: { timeRange } }),
};

// ── AI Remediation endpoints ──────────────────────────────────────────
export const aiAPI = {
    getRemediation: (scanId: string, vulnId: string) =>
        api.post(`/scan/${scanId}/findings/${vulnId}/remediate/`),
};

// ── Target Management endpoints ─────────────────────────────────────
export const targetAPI = {
    getTargets: () => api.get('/scan/targets/'),
    createTarget: (data: { domain: string; display_name: string; tags?: string[] }) =>
        api.post('/scan/targets/', data),
    getTarget: (id: string) => api.get(`/scan/targets/${id}/`),
    updateTarget: (id: string, data: Record<string, unknown>) => api.patch(`/scan/targets/${id}/`, data),
    deleteTarget: (id: string) => api.delete(`/scan/targets/${id}/`),
};

// ── Admin endpoints ─────────────────────────────────────────────────
export const adminAPI = {
    getDashboard: (params?: Record<string, string>) =>
        api.get('/admin/dashboard/', { params }),

    getUsers: (params?: Record<string, string>) =>
        api.get('/admin/users/', { params }),

    createUser: (data: Record<string, unknown>) =>
        api.post('/admin/users/', data),

    updateUser: (id: string, data: Record<string, unknown>) =>
        api.patch(`/admin/users/${id}/`, data),

    deleteUser: (id: string) =>
        api.delete(`/admin/users/${id}/`),

    getScans: (params?: Record<string, string>) =>
        api.get('/admin/scans/', { params }),

    deleteScan: (id: string) =>
        api.delete(`/admin/scans/${id}/`),

    getML: () => api.get('/admin/ml/'),

    trainModel: (modelType: string) =>
        api.post('/admin/ml/', { type: modelType }),

    getSettings: () => api.get('/admin/settings/'),

    updateSettings: (data: Record<string, unknown>) =>
        api.put('/admin/settings/', data),

    // Contact message management
    getContacts: (params?: Record<string, string>) =>
        api.get('/admin/contacts/', { params }),

    replyContact: (id: string, data: { reply?: string; is_read?: boolean }) =>
        api.patch(`/admin/contacts/${id}/`, data),

    deleteContact: (id: string) =>
        api.delete(`/admin/contacts/${id}/`),

    // Job application management
    getApplications: (params?: Record<string, string>) =>
        api.get('/admin/applications/', { params }),

    updateApplication: (id: string, data: { status?: string; admin_notes?: string }) =>
        api.patch(`/admin/applications/${id}/`, data),

    deleteApplication: (id: string) =>
        api.delete(`/admin/applications/${id}/`),

    getToolHealth: () =>
        api.get('/scan/tools/health/'),
};

// ── Learn endpoints ─────────────────────────────────────────────────
export const learnAPI = {
    getArticles: (params?: Record<string, string | number>) =>
        api.get('/learn/articles/', { params }),

    getArticle: (slug: string) =>
        api.get(`/learn/articles/${slug}/`),

    getCategories: () =>
        api.get('/learn/categories/'),

    getTags: () =>
        api.get('/learn/tags/'),
};

// ── Contact endpoints ───────────────────────────────────────────────
export const contactAPI = {
    send: (data: { name: string; email: string; subject: string; message: string }) =>
        api.post('/contact/', data),
};

// ── Careers endpoints ───────────────────────────────────────────────
export const careersAPI = {
    apply: (data: {
        position: string;
        name: string;
        email: string;
        phone?: string;
        coverLetter?: string;
        resumeUrl?: string;
        portfolioUrl?: string;
    }) => api.post('/careers/apply/', data),
};

export default api;
