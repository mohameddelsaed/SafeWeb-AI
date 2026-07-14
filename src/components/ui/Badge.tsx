import type { BadgeProps } from '../../types/components';

export default function Badge({
    children,
    variant = 'default',
    size = 'md',
}: BadgeProps) {
    const baseClasses = 'inline-flex items-center justify-center font-medium rounded-full';

    const variants = {
        critical: 'bg-status-critical/10 text-status-critical border border-status-critical/20 animate-badge-pulse-red',
        high: 'bg-status-high/10 text-status-high border border-status-high/20 animate-badge-pulse-orange',
        medium: 'bg-status-medium/10 text-status-medium border border-status-medium/20 animate-badge-pulse-yellow',
        low: 'bg-status-low/10 text-status-low border border-status-low/20 animate-badge-pulse-green',
        info: 'bg-status-info/10 text-status-info border border-status-info/20',
        success: 'bg-accent-green/10 text-accent-green border border-accent-green/20 animate-badge-pulse-green',
        default: 'bg-bg-tertiary text-text-secondary border border-border-primary',
    };

    const sizes = {
        sm: 'px-2 py-0.5 text-xs',
        md: 'px-3 py-1 text-sm',
    };

    return (
        <span className={`${baseClasses} ${variants[variant]} ${sizes[size]}`}>
            {children}
        </span>
    );
}
