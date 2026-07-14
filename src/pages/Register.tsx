import React, { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import { isValidEmail, validatePassword } from '@utils/validation';
import PasswordStrengthMeter from '@components/ui/PasswordStrengthMeter';
import { useAuth } from '@/contexts/AuthContext';
import { AxiosError } from 'axios';

export default function Register() {
    const navigate = useNavigate();
    const { register, isAuthenticated } = useAuth();
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        password: '',
        confirmPassword: '',
    });
    const [errors, setErrors] = useState({
        name: '',
        email: '',
        password: '',
        confirmPassword: '',
    });
    const [apiError, setApiError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [acceptTerms, setAcceptTerms] = useState(false);

    if (isAuthenticated) {
        return <Navigate to="/dashboard" replace />;
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
        const newErrors = { name: '', email: '', password: '', confirmPassword: '' };
        let isValid = true;

        if (!formData.name.trim()) {
            newErrors.name = 'Full name is required';
            isValid = false;
        }

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
        } else {
            const passwordValidation = validatePassword(formData.password);
            if (!passwordValidation.isValid) {
                newErrors.password = passwordValidation.message;
                isValid = false;
            }
        }

        if (!formData.confirmPassword) {
            newErrors.confirmPassword = 'Please confirm your password';
            isValid = false;
        } else if (formData.password !== formData.confirmPassword) {
            newErrors.confirmPassword = 'Passwords do not match';
            isValid = false;
        }

        setErrors(newErrors);
        return isValid;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!acceptTerms) {
            alert('Please accept the Terms of Service and Privacy Policy');
            return;
        }

        if (!validateForm()) return;

        setIsLoading(true);
        setApiError('');

        try {
            await register(formData);
            navigate('/dashboard', { replace: true });
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string; email?: string[] }>;
            const data = axiosErr.response?.data;
            if (data?.email) {
                setErrors((prev) => ({ ...prev, email: data.email![0] }));
            } else {
                setApiError(
                    data?.detail || data?.message || 'Registration failed. Please try again.',
                );
            }
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
                                Create Your Account
                            </h1>
                            <p className="text-text-secondary">
                                Start securing your web applications today
                            </p>
                        </div>

                        {/* Register Card */}
                        <Card className="p-8">
                            <form onSubmit={handleSubmit} className="space-y-5">
                                {/* API Error */}
                                {apiError && (
                                    <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                        {apiError}
                                    </div>
                                )}

                                {/* OAuth Buttons */}
                                <div className="grid grid-cols-1 gap-3 mb-6">
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
                                        <span>Continue with Google</span>
                                        <span className="absolute right-3 text-[10px] font-semibold uppercase tracking-wider bg-accent-blue/20 text-accent-blue px-2 py-0.5 rounded-full">
                                            Coming Soon
                                        </span>
                                    </button>
                                </div>

                                {/* Divider */}
                                <div className="relative">
                                    <div className="absolute inset-0 flex items-center">
                                        <div className="w-full border-t border-border-primary"></div>
                                    </div>
                                    <div className="relative flex justify-center text-sm">
                                        <span className="px-4 bg-bg-card text-text-tertiary">Or register with email</span>
                                    </div>
                                </div>

                                {/* Full Name Input */}
                                <Input
                                    type="text"
                                    name="name"
                                    label="Full Name"
                                    placeholder="John Doe"
                                    value={formData.name}
                                    onChange={handleChange}
                                    error={errors.name}
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                        </svg>
                                    }
                                />

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
                                <div>
                                    <Input
                                        type="password"
                                        name="password"
                                        label="Password"
                                        placeholder="Create a strong password"
                                        value={formData.password}
                                        onChange={handleChange}
                                        error={errors.password}
                                        leftIcon={
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                            </svg>
                                        }
                                    />
                                    <PasswordStrengthMeter password={formData.password} />
                                </div>

                                {/* Confirm Password Input */}
                                <Input
                                    type="password"
                                    name="confirmPassword"
                                    label="Confirm Password"
                                    placeholder="Re-enter your password"
                                    value={formData.confirmPassword}
                                    onChange={handleChange}
                                    error={errors.confirmPassword}
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    }
                                />

                                {/* Terms Checkbox */}
                                <label className="flex items-start gap-3 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={acceptTerms}
                                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setAcceptTerms(e.target.checked)}
                                        className="w-4 h-4 mt-1 rounded border-border-primary bg-bg-secondary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer flex-shrink-0"
                                    />
                                    <span className="text-sm text-text-secondary leading-relaxed">
                                        I agree to the{' '}
                                        <Link to="/terms" className="text-accent-green hover:text-accent-green-hover">
                                            Terms of Service
                                        </Link>{' '}
                                        and{' '}
                                        <Link to="/privacy" className="text-accent-green hover:text-accent-green-hover">
                                            Privacy Policy
                                        </Link>
                                    </span>
                                </label>

                                {/* Submit Button */}
                                <Button
                                    type="submit"
                                    variant="primary"
                                    size="lg"
                                    className="w-full"
                                    isLoading={isLoading}
                                >
                                    Create Account
                                </Button>
                            </form>
                        </Card>

                        {/* Sign In Link */}
                        <p className="text-center text-sm text-text-tertiary mt-6">
                            Already have an account?{' '}
                            <Link to="/login" className="text-accent-green hover:text-accent-green-hover font-medium transition-colors">
                                Sign in
                            </Link>
                        </p>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
