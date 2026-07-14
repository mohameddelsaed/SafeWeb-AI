import React, { useState } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import { authAPI } from '@/services/api';

export default function ResetPassword() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const token = searchParams.get('token') || '';

    const [formData, setFormData] = useState({ password: '', confirmPassword: '' });
    const [errors, setErrors] = useState({ password: '', confirmPassword: '' });
    const [apiError, setApiError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [isSuccess, setIsSuccess] = useState(false);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        if (errors[name as keyof typeof errors]) {
            setErrors(prev => ({ ...prev, [name]: '' }));
        }
    };

    const validateForm = (): boolean => {
        const newErrors = { password: '', confirmPassword: '' };
        let isValid = true;

        if (!formData.password) {
            newErrors.password = 'Password is required';
            isValid = false;
        } else if (formData.password.length < 8) {
            newErrors.password = 'Password must be at least 8 characters';
            isValid = false;
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
        if (!validateForm()) return;

        setIsLoading(true);
        setApiError('');

        try {
            await authAPI.resetPassword({ token, password: formData.password });
            setIsSuccess(true);
            setTimeout(() => navigate('/login'), 3000);
        } catch {
            setApiError('Invalid or expired reset token. Please request a new password reset.');
        } finally {
            setIsLoading(false);
        }
    };

    if (!token) {
        return (
            <Layout>
                <div className="py-20 min-h-screen flex items-center">
                    <Container maxWidth="content">
                        <div className="max-w-md mx-auto text-center">
                            <Card className="p-8">
                                <svg className="w-16 h-16 mx-auto text-status-critical mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                    Invalid Reset Link
                                </h2>
                                <p className="text-text-secondary mb-6">
                                    This password reset link is invalid or has expired.
                                </p>
                                <Link to="/forgot-password">
                                    <Button variant="primary" size="sm">Request New Link</Button>
                                </Link>
                            </Card>
                        </div>
                    </Container>
                </div>
            </Layout>
        );
    }

    return (
        <Layout>
            <div className="py-20 min-h-screen flex items-center">
                <Container maxWidth="content">
                    <div className="max-w-md mx-auto">
                        <div className="text-center mb-8">
                            <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                Set New Password
                            </h1>
                            <p className="text-text-secondary">
                                Enter your new password below
                            </p>
                        </div>

                        <Card className="p-8">
                            {isSuccess ? (
                                <div className="text-center py-4">
                                    <svg className="w-16 h-16 mx-auto text-accent-green mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    <h2 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                        Password Reset Successfully
                                    </h2>
                                    <p className="text-text-secondary">
                                        Redirecting to sign in...
                                    </p>
                                </div>
                            ) : (
                                <form onSubmit={handleSubmit} className="space-y-6">
                                    {apiError && (
                                        <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                            {apiError}
                                        </div>
                                    )}

                                    <Input
                                        type="password"
                                        name="password"
                                        label="New Password"
                                        placeholder="Enter new password"
                                        value={formData.password}
                                        onChange={handleChange}
                                        error={errors.password}
                                        leftIcon={
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                            </svg>
                                        }
                                    />

                                    <Input
                                        type="password"
                                        name="confirmPassword"
                                        label="Confirm Password"
                                        placeholder="Confirm new password"
                                        value={formData.confirmPassword}
                                        onChange={handleChange}
                                        error={errors.confirmPassword}
                                        leftIcon={
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                            </svg>
                                        }
                                    />

                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        className="w-full"
                                        isLoading={isLoading}
                                    >
                                        Reset Password
                                    </Button>
                                </form>
                            )}
                        </Card>

                        <p className="text-center text-sm text-text-tertiary mt-6">
                            <Link to="/login" className="text-accent-green hover:text-accent-green-hover font-medium transition-colors">
                                Back to Sign In
                            </Link>
                        </p>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
