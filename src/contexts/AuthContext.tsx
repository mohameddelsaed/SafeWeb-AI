import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI, userAPI, setTokens, clearTokens, getAccessToken, getRefreshToken } from '@/services/api';

// ── Types ───────────────────────────────────────────────────────────
export interface User {
    id: string;
    email: string;
    name: string;
    role: string;
    avatar: string | null;
    company: string;
    jobTitle: string;
    plan: string;
    twoFactorEnabled: boolean;
    hasTargets: boolean;
}

interface AuthContextType {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
    register: (data: { name: string; email: string; password: string; confirmPassword: string }) => Promise<void>;
    logout: () => Promise<void>;
    updateUser: (data: Partial<User>) => void;
    refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

// ── Provider ────────────────────────────────────────────────────────
export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    // Check existing token on mount
    useEffect(() => {
        const token = getAccessToken();
        if (token) {
            authAPI
                .verify()
                .then(({ data }) => setUser(data.user))
                .catch(() => {
                    clearTokens();
                    setUser(null);
                })
                .finally(() => setIsLoading(false));
        } else {
            setIsLoading(false);
        }
    }, []);

    const login = useCallback(async (email: string, password: string, rememberMe?: boolean) => {
        const { data } = await authAPI.login({ email, password, rememberMe });
        setTokens(data.tokens.access, data.tokens.refresh);
        setUser(data.user);
    }, []);

    const register = useCallback(
        async (payload: { name: string; email: string; password: string; confirmPassword: string }) => {
            const { data } = await authAPI.register(payload);
            setTokens(data.tokens.access, data.tokens.refresh);
            setUser(data.user);
        },
        [],
    );

    const logout = useCallback(async () => {
        try {
            const refresh = getRefreshToken();
            if (refresh) await authAPI.logout(refresh);
        } catch {
            /* ignore */
        } finally {
            clearTokens();
            setUser(null);
        }
    }, []);

    const updateUser = useCallback((data: Partial<User>) => {
        setUser((prev) => (prev ? { ...prev, ...data } : null));
    }, []);

    const refreshProfile = useCallback(async () => {
        const { data } = await userAPI.getProfile();
        setUser(data);
    }, []);

    return (
        <AuthContext.Provider
            value={{
                user,
                isAuthenticated: !!user,
                isLoading,
                login,
                register,
                logout,
                updateUser,
                refreshProfile,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
}

// ── Hook ────────────────────────────────────────────────────────────
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
    return ctx;
}
