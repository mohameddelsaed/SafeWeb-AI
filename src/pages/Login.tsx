import React, { useState } from 'react';
import { Link, Navigate, useNavigate, useLocation } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import { isValidEmail } from '@utils/validation';
import { useAuth } from '@/contexts/AuthContext';
import { AxiosError } from 'axios';

export default function Login() {
    const navigate = useNavigate();
    const location = useLocation();
    const { login, isAuthenticated } = useAuth();
    const [formData, setFormData] = useState({
        email: '',
        password: '',
    });
    const [errors, setErrors] = useState({
        email: '',
        password: '',
    });
    const [apiError, setApiError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [rememberMe, setRememberMe] = useState(false);

    // Redirect if already authenticated
    if (isAuthenticated) {
        const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';
        return <Navigate to={from} replace />;
    }

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        // Clear error when user types
        if (errors[name as keyof typeof errors]) {
            setErrors((prev) => ({ ...prev, [name]: '' }));
        }
    };

    const validateForm = (): boolean => {
        const newErrors = { email: '', password: '' };
        let isValid = true;

        if (!formData.email) {
            newErrors.email = 'Email is required';
            isValid = false;
        } else if (!isValidEmail(formData.email)) {
            newErrors.email = 'Please enter a valid email address';
            isValid = false;
        }

        if (!formData.password) {
            newErrors.password = 'Password is required';
            isValid = false;
        }

        setErrors(newErrors);
        return isValid;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsLoading(true);
        setApiError('');

        try {
            await login(formData.email, formData.password, rememberMe);
            const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';
            navigate(from, { replace: true });
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string }>;
            setApiError(
                axiosErr.response?.data?.detail ||
                axiosErr.response?.data?.message ||
                'Invalid email or password. Please try again.',
            );
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <Layout>
            <div className="py-20 min-h-screen flex items-center">
                <Container maxWidth="content">
                    <div className="max-w-md mx-auto">
                        {/* Header */}
                        <div className="text-center mb-8">
                            <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                Welcome Back
                            </h1>
                            <p className="text-text-secondary">
                                Sign in to access your security dashboard
                            </p>
                        </div>

                        {/* Login Card */}
                        <Card className="p-8">
                            <form onSubmit={handleSubmit} className="space-y-6">
                                {/* API Error */}
                                {apiError && (
                                    <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                        {apiError}
                                    </div>
                                )}

                                {/* Email Input */}
                                <Input
                                    type="email"
                                    name="email"
                                    label="Email Address"
                                    placeholder="you@example.com"
                                    value={formData.email}
                                    onChange={handleChange}
                                    error={errors.email}
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                                        </svg>
                                    }
                                />

                                {/* Password Input */}
                                <Input
                                    type="password"
                                    name="password"
                                    label="Password"
                                    placeholder="Enter your password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    error={errors.password}
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                        </svg>
                                    }
                                />

                                {/* Remember Me & Forgot Password */}
                                <div className="flex items-center justify-between">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={rememberMe}
                                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setRememberMe(e.target.checked)}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-secondary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <span className="text-sm text-text-secondary">Remember me</span>
                                    </label>
                                    <Link
                                        to="/forgot-password"
                                        className="text-sm text-accent-green hover:text-accent-green-hover transition-colors"
                                    >
                                        Forgot password?
                                    </Link>
                                </div>

                                {/* Submit Button */}
                                <Button
                                    type="submit"
                                    variant="primary"
                                    size="lg"
                                    className="w-full"
                                    isLoading={isLoading}
                                >
                                    Sign In
                                </Button>

                                {/* Divider */}
                                <div className="relative">
                                    <div className="absolute inset-0 flex items-center">
                                        <div className="w-full border-t border-border-primary"></div>
                                    </div>
                                    <div className="relative flex justify-center text-sm">
                                        <span className="px-4 bg-bg-card text-text-tertiary">Or continue with</span>
                                    </div>
                                </div>

                                {/* OAuth Buttons */}
                                <div className="grid grid-cols-1 gap-3">
                                    <button
                                        type="button"
                                        disabled
                                        className="relative flex items-center justify-center gap-3 px-4 py-2.5 rounded-lg bg-bg-secondary border border-border-primary text-text-muted cursor-not-allowed opacity-60"
                                    >
                                        <svg className="w-5 h-5" viewBox="0 0 24 24">
                                            <path
                                                fill="currentColor"
                                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                                            />
                                        </svg>
                                        <span>Sign in with Google</span>
                                        <span className="absolute right-3 text-[10px] font-semibold uppercase tracking-wider bg-accent-blue/20 text-accent-blue px-2 py-0.5 rounded-full">
                                            Coming Soon
                                        </span>
                                    </button>
                                </div>
                            </form>
                        </Card>

                        {/* Sign Up Link */}
                        <p className="text-center text-sm text-text-tertiary mt-6">
                            Don&apos;t have an account?{' '}
                            <Link to="/register" className="text-accent-green hover:text-accent-green-hover font-medium transition-colors">
                                Sign up for free
                            </Link>
                        </p>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
