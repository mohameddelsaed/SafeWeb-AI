import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import { isValidEmail } from '@utils/validation';
import { authAPI } from '@/services/api';

export default function ForgotPassword() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [isSubmitted, setIsSubmitted] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (!email) {
            setError('Email is required');
            return;
        }
        if (!isValidEmail(email)) {
            setError('Please enter a valid email address');
            return;
        }

        setIsLoading(true);
        try {
            await authAPI.forgotPassword(email);
            setIsSubmitted(true);
        } catch {
            // Always show success to prevent email enumeration
            setIsSubmitted(true);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <Layout>
            <div className="py-20 min-h-screen flex items-center">
                <Container maxWidth="content">
                    <div className="max-w-md mx-auto">
                        <div className="text-center mb-8">
                            <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                                Reset Password
                            </h1>
                            <p className="text-text-secondary">
                                Enter your email address and we&apos;ll send you a link to reset your password
                            </p>
                        </div>

                        <Card className="p-8">
                            {isSubmitted ? (
                                <div className="text-center py-4">
                                    <svg className="w-16 h-16 mx-auto text-accent-green mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                    <h2 className="text-xl font-heading font-semibold text-text-primary mb-2">
                                        Check your email
                                    </h2>
                                    <p className="text-text-secondary mb-6">
                                        If an account exists with <strong>{email}</strong>, you&apos;ll receive a password reset link shortly.
                                    </p>
                                    <Link to="/login">
                                        <Button variant="outline" size="sm">
                                            Back to Sign In
                                        </Button>
                                    </Link>
                                </div>
                            ) : (
                                <form onSubmit={handleSubmit} className="space-y-6">
                                    <Input
                                        type="email"
                                        name="email"
                                        label="Email Address"
                                        placeholder="you@example.com"
                                        value={email}
                                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                                            setEmail(e.target.value);
                                            if (error) setError('');
                                        }}
                                        error={error}
                                        leftIcon={
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
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
                                        Send Reset Link
                                    </Button>
                                </form>
                            )}
                        </Card>

                        <p className="text-center text-sm text-text-tertiary mt-6">
                            Remember your password?{' '}
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
