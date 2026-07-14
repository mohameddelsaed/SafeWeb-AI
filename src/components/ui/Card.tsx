import type { CardProps } from '../../types/components';
import { CARD, EASING, prefersReducedMotion } from '@utils/animationConfig';

export default function Card({
    children,
    className = '',
    variant = 'default',
    hover = false,
    glow = 'none',
    id,
    onClick,
}: CardProps) {
    const reduced = prefersReducedMotion();

    const baseClasses = [
        'rounded-lg',
        reduced
            ? 'transition-none'
            : `transition-all duration-[${CARD.transitionMs}ms]`,
    ].join(' ');

    const variants = {
        default: 'bg-bg-card border border-border-primary',
        glass: 'bg-bg-card/50 backdrop-blur-sm border border-border-primary/50',
        bordered: 'bg-transparent border-2 border-border-secondary',
    };

    const hoverClasses = hover && !reduced
        ? 'hover:-translate-y-1.5 hover:shadow-[0_0_15px_rgba(0,255,136,0.15)] hover:border-accent-green/30 cursor-pointer'
        : hover
            ? 'cursor-pointer'
            : '';

    const glowClasses = {
        none: '',
        green: 'shadow-glow-green',
        blue: 'shadow-glow-blue',
    };

    return (
        <div
            id={id}
            className={`${baseClasses} ${variants[variant]} ${hoverClasses} ${glowClasses[glow]} ${className}`}
            style={{ transitionTimingFunction: EASING.default }}
            onClick={onClick}
            role={onClick ? 'button' : undefined}
            tabIndex={onClick ? 0 : undefined}
            onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') onClick(); } : undefined}
        >
            {children}
        </div>
    );
}
