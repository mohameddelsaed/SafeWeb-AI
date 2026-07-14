import { useMemo } from 'react';

interface PasswordStrengthMeterProps {
    password: string;
}

interface Criterion {
    label: string;
    met: boolean;
}

function evaluatePassword(password: string): { score: number; label: string; color: string; criteria: Criterion[] } {
    const criteria: Criterion[] = [
        { label: 'At least 8 characters', met: password.length >= 8 },
        { label: 'Uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
        { label: 'Lowercase letter (a-z)', met: /[a-z]/.test(password) },
        { label: 'Number (0-9)', met: /\d/.test(password) },
        { label: 'Special character (!@#$%^&*)', met: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password) },
    ];

    const metCount = criteria.filter((c) => c.met).length;

    // Bonus for length
    let score = metCount;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Normalize to 0-4 scale
    const normalizedScore = Math.min(4, Math.floor((score / 7) * 4));

    const levels = [
        { label: 'Very Weak', color: '#ef4444' },
        { label: 'Weak', color: '#f97316' },
        { label: 'Fair', color: '#eab308' },
        { label: 'Strong', color: '#22c55e' },
        { label: 'Very Strong', color: '#10b981' },
    ];

    const level = levels[normalizedScore];

    return {
        score: normalizedScore,
        label: level.label,
        color: level.color,
        criteria,
    };
}

export default function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
    const { score, label, color, criteria } = useMemo(() => evaluatePassword(password), [password]);

    if (!password) return null;

    return (
        <div className="mt-2 space-y-2">
            {/* Strength bar */}
            <div className="flex items-center gap-2">
                <div className="flex-1 flex gap-1">
                    {[0, 1, 2, 3].map((i) => (
                        <div
                            key={i}
                            className="h-1.5 flex-1 rounded-full transition-all duration-300"
                            style={{
                                backgroundColor: i <= score ? color : 'rgba(255,255,255,0.1)',
                            }}
                        />
                    ))}
                </div>
                <span className="text-xs font-medium min-w-[80px] text-right" style={{ color }}>
                    {label}
                </span>
            </div>

            {/* Criteria checklist */}
            <div className="grid grid-cols-1 gap-0.5">
                {criteria.map((c) => (
                    <div key={c.label} className="flex items-center gap-1.5 text-xs">
                        <span className={c.met ? 'text-accent-green' : 'text-text-muted'}>
                            {c.met ? '✓' : '○'}
                        </span>
                        <span className={c.met ? 'text-text-secondary' : 'text-text-muted'}>
                            {c.label}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}
