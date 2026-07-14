import type { ButtonProps } from '../../types/components';
import { BUTTON, EASING, prefersReducedMotion } from '@utils/animationConfig';

export default function Button({
    variant = 'primary',
    size = 'md',
    isLoading = false,
    leftIcon,
    rightIcon,
    className = '',
    children,
    disabled,
    ...props
}: ButtonProps) {
    const reduced = prefersReducedMotion();

    const baseClasses = [
        'btn-border-trace relative inline-flex items-center justify-center gap-2 font-medium',
        'focus-visible-custom disabled:opacity-50 disabled:cursor-not-allowed',
        reduced
            ? 'transition-none'
            : `transition-[transform,filter] duration-[${BUTTON.transitionMs}ms]`,
        !reduced && 'hover:-translate-y-[2px] active:translate-y-0 active:scale-[0.98]',
    ].filter(Boolean).join(' ');

    const variants = {
        primary:
            'bg-accent-green text-bg-primary hover:bg-accent-green-hover hover:drop-shadow-[0_0_14px_rgba(0,255,136,0.45)]',
        secondary:
            'bg-accent-blue text-text-primary hover:bg-accent-blue-hover hover:drop-shadow-[0_0_14px_rgba(58,169,255,0.4)]',
        outline:
            'border-2 border-accent-green text-accent-green hover:bg-accent-green hover:text-bg-primary hover:drop-shadow-[0_0_12px_rgba(0,255,136,0.35)]',
        ghost:
            'text-accent-green hover:bg-accent-green/10 hover:drop-shadow-[0_0_10px_rgba(0,255,136,0.25)]',
        danger:
            'bg-status-critical text-text-primary hover:bg-status-critical/80 hover:drop-shadow-[0_0_12px_rgba(255,59,59,0.4)]',
    };

    const sizes = {
        sm: 'px-3 py-1.5 text-sm rounded',
        md: 'px-5 py-2.5 text-base rounded-lg',
        lg: 'px-7 py-3.5 text-lg rounded-lg',
    };

    return (
        <button
            className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
            disabled={disabled || isLoading}
            style={{ transitionTimingFunction: EASING.snappy }}
            {...props}
        >
            {isLoading ? (
                <>
                    <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>Loading...</span>
                </>
            ) : (
                <>
                    {leftIcon && <span className="flex-shrink-0">{leftIcon}</span>}
                    {children}
                    {rightIcon && <span className="flex-shrink-0">{rightIcon}</span>}
                </>
            )}
        </button>
    );
}
